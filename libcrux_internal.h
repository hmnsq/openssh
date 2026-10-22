/*  $OpenBSD: libcrux_internal.h,v 1.1 2026/06/14 03:59:34 djm Exp $ */

/* Extracted from libcrux revision c46481ce3cd1cc8315e90db114581d8c992c3d7d */

/*
 * MIT License
 *
 * Copyright (c) 2024 Cryspen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ఒకవేళ !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#అయితే_ముగింపు
#నిర్వచించు KRML_MUSTINLINE అంతఃవరుస
#నిర్వచించు KRML_NOINLINE __attribute__((noinline, వాడని))
#నిర్వచించు KRML_HOST_EPRINTF(...)
#నిర్వచించు KRML_HOST_EXIT(x) fatal_f("internal error")
#నిర్వచించు KRML_UNION_CONSTRUCTOR(T)

స్థిర అంతఃవరుస శూన్య
store64_le(uint8_t dst[8], uint64_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
	dst[2] = (src >> 16) & 0xff;
	dst[3] = (src >> 24) & 0xff;
	dst[4] = (src >> 32) & 0xff;
	dst[5] = (src >> 40) & 0xff;
	dst[6] = (src >> 48) & 0xff;
	dst[7] = (src >> 56) & 0xff;
}

స్థిర అంతఃవరుస శూన్య
store32_le(uint8_t dst[4], uint32_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
	dst[2] = (src >> 16) & 0xff;
	dst[3] = (src >> 24) & 0xff;
}

స్థిర అంతఃవరుస శూన్య
store16_le(uint8_t dst[2], uint16_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
}

స్థిర అంతఃవరుస శూన్య
store32_be(uint8_t dst[4], uint32_t src)
{
	dst[0] = (src >> 24) & 0xff;
	dst[1] = (src >> 16) & 0xff;
	dst[2] = (src >> 8) & 0xff;
	dst[3] = src & 0xff;
}

స్థిర అంతఃవరుస uint64_t
load64_le(uint8_t src[8])
{
	తిరిగి (uint64_t)(src[0]) |
	    ((uint64_t)(src[1]) << 8) |
	    ((uint64_t)(src[2]) << 16) |
	    ((uint64_t)(src[3]) << 24) |
	    ((uint64_t)(src[4]) << 32) |
	    ((uint64_t)(src[5]) << 40) |
	    ((uint64_t)(src[6]) << 48) |
	    ((uint64_t)(src[7]) << 56);
}

స్థిర అంతఃవరుస uint32_t
load32_le(uint8_t src[4])
{
	తిరిగి (uint32_t)(src[0]) |
	    ((uint32_t)(src[1]) << 8) |
	    ((uint32_t)(src[2]) << 16) |
	    ((uint32_t)(src[3]) << 24);
}

స్థిర అంతఃవరుస uint16_t
load16_le(uint8_t src[4])
{
	తిరిగి (uint16_t)(src[0]) |
	    ((uint16_t)(src[1]) << 8);
}

#నిర్వచితమైతే MISSING_BUILTIN_POPCOUNT
స్థిర అంతఃవరుస గుర్తులేని పూర్ణాంకం
__builtin_popcount(గుర్తులేని పూర్ణాంకం అంకె)
{
  స్థిరరాశి పూర్ణాంకం v[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
  తిరిగి v[అంకె & 0xf] + v[(అంకె >> 4) & 0xf];
}
#అయితే_ముగింపు

/* from libcrux/combined_extraction/generated/eurydice_glue.h */
#సూచన once


#నిర్వచితమైతే _MSC_VER
// For __popcnt
#అయితే_ముగింపు


// C++ HELPERS

#ఒకవేళ defined(__cplusplus)

#నిర్వచితం_కాకపోతే KRML_HOST_EPRINTF
#నిర్వచించు KRML_HOST_EPRINTF(...) fprintf(stderr, __VA_ARGS__)
#అయితే_ముగింపు


#నిర్వచితం_కాకపోతే __cpp_lib_type_identity
మూస <class T>
నిర్మాణం type_తటస్థం {
  using type = T;
};

మూస <class T>
using type_తటస్థం_t = typename type_తటస్థం<T>::type;
#లేకపోతే
using std::type_తటస్థం_t;
#అయితే_ముగింపు

#నిర్వచించు KRML_UNION_CONSTRUCTOR(T)                              \
  మూస <typename V>                                        \
  constexpr T(పూర్ణాంకం t, V U::*m, type_తటస్థం_t<V> v) : ట్యాగ్(t) { \
    val.*m = std::move(v);                                     \
  }                                                            \
  T() = అప్రమేయ;

#అయితే_ముగింపు

// GENERAL-PURPOSE STUFF

#నిర్వచించు దిగువ_నక్షత్రం_Ignore_ignore(e, t, _ret_t) ((శూన్య)e)

#నిర్వచించు EURYDICE_ASSERT(test, సందేశం)                                            \
  చేయి {                                                                        \
    ఒకవేళ (!(test)) {                                                            \
      fprintf(stderr, "assertion \"%s\" failed: file \"%s\", line %d\n", సందేశం, \
              __FILE__, __LINE__);                                            \
      నిష్క్రమించు(255);                                                              \
    }                                                                         \
  } అయితే (0)

// SIZEOF, ALIGNOF

#నిర్వచించు Eurydice_sizeof(t) పరిమాణం(t)

#నిర్వచించు Eurydice_alignof(t) alignof(t)

// SLICES, ARRAYS, ETC.

// For convenience, we give these common slice types, below, a distinguished
// status and rather than emit them in the client code, we skip their
// code-generation in Cleanup3.ml and write them by hand here. This makes it
// easy to write interop code that brings those definitions in scope.

// &[u8]
రకనిర్వచనం నిర్మాణం Eurydice_borrow_ముక్క_u8_s {
  స్థిరరాశి uint8_t *ptr;
  కొలత_t meta;
} Eurydice_borrow_ముక్క_u8;

// &[u16]
రకనిర్వచనం నిర్మాణం Eurydice_borrow_ముక్క_i16_s {
  స్థిరరాశి int16_t *ptr;
  కొలత_t meta;
} Eurydice_borrow_ముక్క_i16;

// &mut [u8]
రకనిర్వచనం నిర్మాణం Eurydice_mut_borrow_ముక్క_u8_s {
  uint8_t *ptr;
  కొలత_t meta;
} Eurydice_mut_borrow_ముక్క_u8;

// &mut [u16]
రకనిర్వచనం నిర్మాణం Eurydice_mut_borrow_ముక్క_i16_s {
  int16_t *ptr;
  కొలత_t meta;
} Eurydice_mut_borrow_ముక్క_i16;

#ఒకవేళ defined(__cplusplus)
#నిర్వచించు KRML_CLITERAL(type) type
#లేకపోతే
#నిర్వచించు KRML_CLITERAL(type) (type)
#అయితే_ముగింపు

#ఒకవేళ defined(__cplusplus) && defined(__cpp_designated_initializers) || \
    !(defined(__cplusplus))
#నిర్వచించు EURYDICE_CFIELD(X) X
#లేకపోతే
#నిర్వచించు EURYDICE_CFIELD(X)
#అయితే_ముగింపు

#నిర్వచించు Eurydice_array_repeat(dst, len, init, t) \
  ERROR "should've been desugared"

// Copy a slice with memcopy
#నిర్వచించు Eurydice_ముక్క_copy(dst, src, t) \
  జ్ఞాపకం_నకలు(dst.ptr, src.ptr, dst.meta * పరిమాణం(t))

#నిర్వచించు core_array_T_N_as_ముక్క(len_, ptr_, t, ret_t)   \
  (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ptr =)(ptr_)->దత్తాంశం, \
                        EURYDICE_CFIELD(.meta =) len_})

#నిర్వచించు core_array__core__clone__Clone_for__T__N___clone(len, src, elem_type, \
                                                         _ret_t)              \
  (*(src))
#నిర్వచించు Try_From_ముక్క_Error uint8_t
#నిర్వచించు core_array_Try_From_ముక్క_Error uint8_t

// Distinguished support for some PartialEq trait implementations
//
// core::cmp::PartialEq<@Array<U, N>> for @Array<T, N>
#నిర్వచించు Eurydice_array_eq(sz, a1, a2, t) \
  (memcmp((a1)->దత్తాంశం, (a2)->దత్తాంశం, sz * పరిమాణం(t)) == 0)
// core::cmp::PartialEq<&0 (@Slice<U>)> for @Array<T, N>
#నిర్వచించు Eurydice_array_eq_ముక్క_shared(sz, a1, s2, t, _) \
  (memcmp((a1)->దత్తాంశం, (s2)->ptr, sz * పరిమాణం(t)) == 0)
#నిర్వచించు Eurydice_array_eq_ముక్క_mut(sz, a1, s2, t, _) \
  Eurydice_array_eq_ముక్క_shared(sz, a1, s2, t, _)

// DEPRECATED -- should no longer be generated
#నిర్వచించు core_array_equality__core__cmp__PartialEq__Array_U__N___for__Array_T__N___eq( \
    sz, a1, a2, t, _, _ret_t)                                                         \
  Eurydice_array_eq(sz, a1, a2, t)
#నిర్వచించు core_array_equality_core_cmp_Partial_Eq_0_ముక్క_U_for_Array_T_N_eq( \
    sz, a1, a2, t, _, _ret_t)                                                           \
  Eurydice_array_eq(sz, a1, ((a2)->ptr), t)
#నిర్వచించు core_cmp_impls__core__cmp__PartialEq__0_mut__B___for__1_mut__A___eq( \
    _m0, _m1, src1, src2, _0, _1, T)                                         \
  Eurydice_ముక్క_eq(src1, src2, _, _, T, _)

#నిర్వచించు Eurydice_ముక్క_విభజించు_at(ముక్క, mid, element_type, ret_t)        \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((ముక్క).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((ముక్క).ptr + mid), EURYDICE_CFIELD(.meta =)((ముక్క).meta - mid) \
    }                                                                   \
  }

#నిర్వచించు Eurydice_ముక్క_విభజించు_at_mut(ముక్క, mid, element_type, ret_t)    \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((ముక్క).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((ముక్క).ptr + mid), EURYDICE_CFIELD(.meta =)((ముక్క).meta - mid) \
    }                                                                   \
  }

// Conversion of slice to an array, rewritten (by Eurydice) to name the
// destination array, since arrays are not values in C.
// N.B.: see note in karamel/lib/Inlining.ml if you change this.

#నిర్వచించు Eurydice_ముక్క_గమ్యం_ref_array2(len_, src, arr_ptr, t_ptr, t_arr, t_err, \
                                     t_res)                                   \
  (src.meta >= len_                                                           \
       ? ((t_res){.ట్యాగ్ = core_ఫలితం_Ok, .val = {.case_Ok = arr_ptr}})        \
       : ((t_res){.ట్యాగ్ = core_ఫలితం_Err, .val = {.case_Err = 0}}))

// CORE STUFF (conversions, endianness, ...)

// We slap extern "C" on declarations that intend to implement a prototype
// generated by Eurydice, because Eurydice prototypes are always emitted within
// an extern "C" block, UNLESS you use -fcxx17-compat, in which case, you must
// pass -DKRML_CXX17_COMPAT="" to your C++ compiler.
#ఒకవేళ defined(__cplusplus) && !defined(KRML_CXX17_COMPAT)
బాహ్య "C" {
#అయితే_ముగింపు

#నిర్వచించు core_hint_black_box(X, _0, _1) (X)

// [ u8; 2 ]
రకనిర్వచనం నిర్మాణం Eurydice_array_u8x2_s {
  uint8_t దత్తాంశం[2];
} Eurydice_array_u8x2;

// [ u8; 4 ]
రకనిర్వచనం నిర్మాణం Eurydice_array_u8x4_s {
  uint8_t దత్తాంశం[4];
} Eurydice_array_u8x4;

// [ u8; 8 ]
రకనిర్వచనం నిర్మాణం Eurydice_array_u8x8_s {
  uint8_t దత్తాంశం[8];
} Eurydice_array_u8x8;

స్థిర అంతఃవరుస uint16_t core_అంకె_u16_from_le_బైట్లు(Eurydice_array_u8x2 buf) {
  తిరిగి load16_le(buf.దత్తాంశం);
}

స్థిర అంతఃవరుస Eurydice_array_u8x4 core_అంకె_u32_గమ్యం_be_బైట్లు(uint32_t src) {
  // TODO: why not store32_be?
  Eurydice_array_u8x4 a;
  uint32_t x = htobe32(src);
  జ్ఞాపకం_నకలు(a.దత్తాంశం, &x, 4);
  తిరిగి a;
}

స్థిర అంతఃవరుస Eurydice_array_u8x4 core_అంకె_u32_గమ్యం_le_బైట్లు(uint32_t src) {
  Eurydice_array_u8x4 a;
  store32_le(a.దత్తాంశం, src);
  తిరిగి a;
}

స్థిర అంతఃవరుస uint32_t core_అంకె_u32_from_le_బైట్లు(Eurydice_array_u8x4 buf) {
  తిరిగి load32_le(buf.దత్తాంశం);
}

స్థిర అంతఃవరుస Eurydice_array_u8x8 core_అంకె_u64_గమ్యం_le_బైట్లు(uint64_t v) {
  Eurydice_array_u8x8 a;
  store64_le(a.దత్తాంశం, v);
  తిరిగి a;
}

స్థిర అంతఃవరుస uint64_t core_అంకె_u64_from_le_బైట్లు(Eurydice_array_u8x8 buf) {
  తిరిగి load64_le(buf.దత్తాంశం);
}

స్థిర అంతఃవరుస int64_t core_convert_అంకె_core_convert_From_i32_for_i64_from(
    int32_t x) {
  తిరిగి x;
}

స్థిర అంతఃవరుస uint64_t core_convert_అంకె_core_convert_From_u8_for_u64_from(
    uint8_t x) {
  తిరిగి x;
}

స్థిర అంతఃవరుస uint64_t core_convert_అంకె_core_convert_From_u16_for_u64_from(
    uint16_t x) {
  తిరిగి x;
}

స్థిర అంతఃవరుస కొలత_t core_convert_అంకె_core_convert_From_u16_for_usize_from(
    uint16_t x) {
  తిరిగి x;
}

స్థిర అంతఃవరుస uint32_t core_అంకె_u8_లెక్క_ones(uint8_t x0) {
#నిర్వచితమైతే _MSC_VER
  తిరిగి __popcnt(x0);
#లేకపోతే
  తిరిగి __builtin_popcount(x0);
#అయితే_ముగింపు
}

స్థిర అంతఃవరుస uint32_t core_అంకె_u32_లెక్క_ones(uint32_t x0) {
#నిర్వచితమైతే _MSC_VER
  తిరిగి __popcnt(x0);
#లేకపోతే
  తిరిగి __builtin_popcount(x0);
#అయితే_ముగింపు
}

స్థిర అంతఃవరుస uint32_t core_అంకె_i32_లెక్క_ones(int32_t x0) {
#నిర్వచితమైతే _MSC_VER
  తిరిగి __popcnt(x0);
#లేకపోతే
  తిరిగి __builtin_popcount(x0);
#అయితే_ముగింపు
}

స్థిర అంతఃవరుస కొలత_t core_cmp_impls__core__cmp__Ord_for_usize__min(కొలత_t a,
                                                                   కొలత_t b) {
  ఒకవేళ (a <= b)
    తిరిగి a;
  లేకపోతే
    తిరిగి b;
}

// unsigned overflow wraparound semantics in C
స్థిర అంతఃవరుస uint8_t core_అంకె_u8_wrapping_sub(uint8_t x, uint8_t y) {
  తిరిగి x - y;
}
స్థిర అంతఃవరుస uint8_t core_అంకె_u8_wrapping_కూడు(uint8_t x, uint8_t y) {
  తిరిగి x + y;
}
స్థిర అంతఃవరుస uint8_t core_అంకె_u8_wrapping_mul(uint8_t x, uint8_t y) {
  తిరిగి x * y;
}
స్థిర అంతఃవరుస uint16_t core_అంకె_u16_wrapping_sub(uint16_t x, uint16_t y) {
  తిరిగి x - y;
}
స్థిర అంతఃవరుస uint16_t core_అంకె_u16_wrapping_కూడు(uint16_t x, uint16_t y) {
  తిరిగి x + y;
}
స్థిర అంతఃవరుస uint16_t core_అంకె_u16_wrapping_mul(uint16_t x, uint16_t y) {
  తిరిగి x * y;
}
స్థిర అంతఃవరుస uint32_t core_అంకె_u32_wrapping_sub(uint32_t x, uint32_t y) {
  తిరిగి x - y;
}
స్థిర అంతఃవరుస uint32_t core_అంకె_u32_wrapping_కూడు(uint32_t x, uint32_t y) {
  తిరిగి x + y;
}
స్థిర అంతఃవరుస uint32_t core_అంకె_u32_wrapping_mul(uint32_t x, uint32_t y) {
  తిరిగి x * y;
}
స్థిర అంతఃవరుస uint64_t core_అంకె_u64_wrapping_sub(uint64_t x, uint64_t y) {
  తిరిగి x - y;
}
స్థిర అంతఃవరుస uint64_t core_అంకె_u64_wrapping_కూడు(uint64_t x, uint64_t y) {
  తిరిగి x + y;
}
స్థిర అంతఃవరుస uint64_t core_అంకె_u64_wrapping_mul(uint64_t x, uint64_t y) {
  తిరిగి x * y;
}
స్థిర అంతఃవరుస కొలత_t core_అంకె_usize_wrapping_sub(కొలత_t x, కొలత_t y) {
  తిరిగి x - y;
}
స్థిర అంతఃవరుస కొలత_t core_అంకె_usize_wrapping_కూడు(కొలత_t x, కొలత_t y) {
  తిరిగి x + y;
}
స్థిర అంతఃవరుస కొలత_t core_అంకె_usize_wrapping_mul(కొలత_t x, కొలత_t y) {
  తిరిగి x * y;
}

స్థిర అంతఃవరుస int8_t core_అంకె_i8_wrapping_కూడు(int8_t x, int8_t y) {
  తిరిగి (int8_t)((uint8_t)x + (uint8_t)y);
}
స్థిర అంతఃవరుస int8_t core_అంకె_i8_wrapping_sub(int8_t x, int8_t y) {
  తిరిగి (int8_t)((uint8_t)x - (uint8_t)y);
}
స్థిర అంతఃవరుస int8_t core_అంకె_i8_wrapping_mul(int8_t x, int8_t y) {
  తిరిగి (int8_t)((uint8_t)x * (uint8_t)y);
}
స్థిర అంతఃవరుస int16_t core_అంకె_i16_wrapping_కూడు(int16_t x, int16_t y) {
  తిరిగి (int16_t)((uint16_t)x + (uint16_t)y);
}
స్థిర అంతఃవరుస int16_t core_అంకె_i16_wrapping_sub(int16_t x, int16_t y) {
  తిరిగి (int16_t)((uint16_t)x - (uint16_t)y);
}
స్థిర అంతఃవరుస int16_t core_అంకె_i16_wrapping_mul(int16_t x, int16_t y) {
  తిరిగి (int16_t)((uint16_t)x * (uint16_t)y);
}
స్థిర అంతఃవరుస int32_t core_అంకె_i32_wrapping_కూడు(int32_t x, int32_t y) {
  తిరిగి (int32_t)((uint32_t)x + (uint32_t)y);
}
స్థిర అంతఃవరుస int32_t core_అంకె_i32_wrapping_sub(int32_t x, int32_t y) {
  తిరిగి (int32_t)((uint32_t)x - (uint32_t)y);
}
స్థిర అంతఃవరుస int32_t core_అంకె_i32_wrapping_mul(int32_t x, int32_t y) {
  తిరిగి (int32_t)((uint32_t)x * (uint32_t)y);
}
స్థిర అంతఃవరుస int64_t core_అంకె_i64_wrapping_కూడు(int64_t x, int64_t y) {
  తిరిగి (int64_t)((uint64_t)x + (uint64_t)y);
}
స్థిర అంతఃవరుస int64_t core_అంకె_i64_wrapping_sub(int64_t x, int64_t y) {
  తిరిగి (int64_t)((uint64_t)x - (uint64_t)y);
}
స్థిర అంతఃవరుస int64_t core_అంకె_i64_wrapping_mul(int64_t x, int64_t y) {
  తిరిగి (int64_t)((uint64_t)x * (uint64_t)y);
}
స్థిర అంతఃవరుస int8_t core_అంకె_i8_wrapping_neg(int8_t x) {
  తిరిగి (int8_t)(-(uint8_t)x);
}
స్థిర అంతఃవరుస int16_t core_అంకె_i16_wrapping_neg(int16_t x) {
  తిరిగి (int16_t)(-(uint16_t)x);
}
స్థిర అంతఃవరుస int32_t core_అంకె_i32_wrapping_neg(int32_t x) {
  తిరిగి (int32_t)(-(uint32_t)x);
}
స్థిర అంతఃవరుస int64_t core_అంకె_i64_wrapping_neg(int64_t x) {
  తిరిగి (int64_t)(-(uint64_t)x);
}

స్థిర అంతఃవరుస uint64_t core_అంకె_u64_rotate_ఎడమ(uint64_t x0, uint32_t x1) {
  తిరిగి (x0 << x1) | (x0 >> ((-x1) & 63));
}

స్థిర అంతఃవరుస శూన్య core_ops_arith_i32_కూడు_కేటాయించు(int32_t *x0, int32_t *x1) {
  *x0 = *x0 + *x1;
}

స్థిర అంతఃవరుస uint8_t Eurydice_bitand_pv_u8(స్థిరరాశి uint8_t *p, uint8_t v) {
  తిరిగి (*p) & v;
}
స్థిర అంతఃవరుస uint8_t Eurydice_shr_pv_u8(స్థిరరాశి uint8_t *p, int32_t v) {
  తిరిగి (*p) >> v;
}
స్థిర అంతఃవరుస uint32_t Eurydice_min_u32(uint32_t x, uint32_t y) {
  తిరిగి x < y ? x : y;
}

స్థిర అంతఃవరుస uint8_t
core_ops_బిట్టు_core_ops_బిట్టు_బిట్టు_And_u8_u8_for_0_u8_bitand(
    స్థిరరాశి uint8_t *x0, uint8_t x1) {
  తిరిగి Eurydice_bitand_pv_u8(x0, x1);
}

స్థిర అంతఃవరుస uint8_t
core_ops_బిట్టు_core_ops_బిట్టు_Shr_i32_u8_for_0_u8_shr(స్థిరరాశి uint8_t *x0,
                                                            int32_t x1) {
  తిరిగి Eurydice_shr_pv_u8(x0, x1);
}

#నిర్వచించు core_అంకె_nonzero_వ్యక్తిగత_Non_Zero_Usize_Inner కొలత_t
స్థిర అంతఃవరుస core_అంకె_nonzero_వ్యక్తిగత_Non_Zero_Usize_Inner
core_అంకె_nonzero_వ్యక్తిగత_core_clone_Clone_for_core_అంకె_nonzero_వ్యక్తిగత_Non_Zero_Usize_Inner_clone(
    core_అంకె_nonzero_వ్యక్తిగత_Non_Zero_Usize_Inner *x0) {
  తిరిగి *x0;
}

#ఒకవేళ defined(__cplusplus) && !defined(KRML_CXX17_COMPAT)
}
#అయితే_ముగింపు

// ITERATORS

#నిర్వచించు Eurydice_range_iter_తదుపరి(iter_ptr, t, ret_t)      \
  (((iter_ptr)->ప్రారంభం >= (iter_ptr)->చివర)                 \
       ? (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ట్యాగ్ =) 0, \
                               EURYDICE_CFIELD(.f0 =) 0}) \
       : (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ట్యాగ్ =) 1, \
                               EURYDICE_CFIELD(.f0 =)(iter_ptr)->ప్రారంభం++}))

#నిర్వచించు core_iter_range_core_iter_traits_iterator_Iterator_A_for_core_ops_range_Range_A_Trait_Clause_0_తదుపరి \
  Eurydice_range_iter_తదుపరి

// See note in karamel/lib/Inlining.ml if you change this
#నిర్వచించు Eurydice_into_iter(x, t, _ret_t, _) (x)
#నిర్వచించు core_iter_traits_collect_core_iter_traits_collect_Into_Iterator_Clause1_అంశం_I_for_I_into_iter \
  Eurydice_into_iter

//అక్షరశ్రేణులు

రకనిర్వచనం అక్షరం Eurydice_c_char_t;
రకనిర్వచనం స్థిరరాశి Eurydice_c_char_t *Prims_string;
రకనిర్వచనం శూన్య Eurydice_c_void_t;

// UNSAFE CODE

#నిర్వచించు core_ముక్క_ముక్క_T_as_mut_ptr(x, t, _) (x.ptr)
#నిర్వచించు core_mem_కొలత_యొక్క(t, _) (పరిమాణం(t))
#నిర్వచించు core_ముక్క_raw_from_raw_parts_mut(ptr, len, _0, _1) \
  (KRML_CLITERAL(Eurydice_ముక్క){(శూన్య *)(ptr), len})
#నిర్వచించు core_ముక్క_raw_from_raw_parts(ptr, len, _0, _1) \
  (KRML_CLITERAL(Eurydice_ముక్క){(శూన్య *)(ptr), len})

// FIXME: add dedicated extraction to extract NonNull<T> as T*
#నిర్వచించు core_ptr_non_null_NonNull శూన్య *

// PRINTING
//
// This is temporary. Ultimately we want to be able to extract all of this.

రకనిర్వచనం శూన్య *core_fmt_Formatter;
#నిర్వచించు core_fmt_rt_core_fmt_rt_వాదం_a_new_display(x1, x2, x3, x4) \
  ఖాళీ

// BOXES

#నిర్వచితం_కాకపోతే EURYDICE_MALLOC
#నిర్వచించు EURYDICE_MALLOC జ్ఞాపకం_ఇవ్వు
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే EURYDICE_REALLOC
#నిర్వచించు EURYDICE_REALLOC realloc
#అయితే_ముగింపు

స్థిర అంతఃవరుస అక్షరం *malloc_and_init(కొలత_t sz, అక్షరం *init) {
  అక్షరం *ptr = (అక్షరం *)EURYDICE_MALLOC(sz);
  ఒకవేళ (ptr != ఖాళీ) జ్ఞాపకం_నకలు(ptr, init, sz);
  తిరిగి ptr;
}

#నిర్వచించు Eurydice_box_new(init, t, t_dst) \
  ((t_dst)(malloc_and_init(పరిమాణం(t), (అక్షరం *)(&init))))

// Initializer for array of size zero
#నిర్వచించు Eurydice_ఖాళీలు_array(dummy, t, t_dst) ((t_dst){.దత్తాంశం = {}})

#నిర్వచించు Eurydice_box_new_array(len, ptr, t, t_dst) \
  ((t_dst)(malloc_and_init(len * పరిమాణం(t), (అక్షరం *)(ptr))))

// FIXME this needs to handle allocation failure errors, but this seems hard to
// do without evaluating malloc_and_init twice...
#నిర్వచించు alloc_boxed__alloc__boxed__Box_T___try_new(init, t, t_ret) \
  ((t_ret){.ట్యాగ్ = core_ఫలితం_Ok,                                  \
           .f0 = (t *)malloc_and_init(పరిమాణం(t), (అక్షరం *)(&init))})

// OPTIONS

#నిర్వచించు core_option__core__option__Option_T__TraitClause_0___is_some( \
    x, యొక్క_type, _)                                                   \
  x->ట్యాగ్

/* from libcrux/combined_extraction/generated/combined_core.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే combined_core_H
#నిర్వచించు combined_core_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు

స్థిర అంతఃవరుస uint32_t core_అంకె_i32_లెక్క_ones(int32_t x0);

స్థిర అంతఃవరుస uint16_t core_అంకె_u16_wrapping_కూడు(uint16_t x0, uint16_t x1);

స్థిర అంతఃవరుస uint64_t core_అంకె_u64_from_le_బైట్లు(Eurydice_array_u8x8 x0);

స్థిర అంతఃవరుస uint64_t core_అంకె_u64_rotate_ఎడమ(uint64_t x0, uint32_t x1);

స్థిర అంతఃవరుస Eurydice_array_u8x8 core_అంకె_u64_గమ్యం_le_బైట్లు(uint64_t x0);

స్థిర అంతఃవరుస uint32_t core_అంకె_u8_లెక్క_ones(uint8_t x0);

స్థిర అంతఃవరుస uint8_t core_అంకె_u8_wrapping_sub(uint8_t x0, uint8_t x1);

స్థిర అంతఃవరుస uint8_t
core_ops_బిట్టు_core_ops_బిట్టు_బిట్టు_And_u8_u8_for_0_u8_bitand(స్థిరరాశి uint8_t *x0, uint8_t x1);

స్థిర అంతఃవరుస uint8_t
core_ops_బిట్టు_core_ops_బిట్టు_Shr_i32_u8_for_0_u8_shr(స్థిరరాశి uint8_t *x0, int32_t x1);

/**
A monomorphic instance of core.ops.range.Range
with types size_t

*/
రకనిర్వచనం నిర్మాణం core_ops_range_Range_87_s
{
  కొలత_t ప్రారంభం;
  కొలత_t చివర;
}
core_ops_range_Range_87;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_i16
Eurydice_ముక్క_subslice_mut_a6(Eurydice_mut_borrow_ముక్క_i16 s, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_i16){
        .ptr = s.ptr + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $16size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_b2_s { uint8_t దత్తాంశం[16U]; } Eurydice_arr_b2;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_b2
with const generics
- $256size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_87_s { Eurydice_arr_b2 దత్తాంశం[256U]; } Eurydice_arr_87;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $24size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_94_s { uint8_t దత్తాంశం[24U]; } Eurydice_arr_94;

#నిర్వచించు core_ఫలితం_Ok 0
#నిర్వచించు core_ఫలితం_Err 1

రకనిర్వచనం uint8_t core_ఫలితం_ఫలితం_57_ట్యాగులు;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_94, core_array_TryFromSliceError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_57_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  సంఘం {
    Eurydice_arr_94 case_Ok;
    core_array_Try_From_ముక్క_Error case_Err;
  }
  val;
}
core_ఫలితం_ఫలితం_57;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$24size_t]], core_array_TryFromSliceError

*/
స్థిర అంతఃవరుస Eurydice_arr_94 core_ఫలితం_unwrap_26_78(core_ఫలితం_ఫలితం_57 self)
{
  ఒకవేళ (self.ట్యాగ్ == core_ఫలితం_Ok)
  {
    తిరిగి self.val.case_Ok;
  }
  లేకపోతే
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $16size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_d6_s { int16_t దత్తాంశం[16U]; } Eurydice_arr_d6;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $20size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_fc_s { uint8_t దత్తాంశం[20U]; } Eurydice_arr_fc;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_fc, core_array_TryFromSliceError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_83_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  సంఘం {
    Eurydice_arr_fc case_Ok;
    core_array_Try_From_ముక్క_Error case_Err;
  }
  val;
}
core_ఫలితం_ఫలితం_83;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$20size_t]], core_array_TryFromSliceError

*/
స్థిర అంతఃవరుస Eurydice_arr_fc core_ఫలితం_unwrap_26_7d(core_ఫలితం_ఫలితం_83 self)
{
  ఒకవేళ (self.ట్యాగ్ == core_ఫలితం_Ok)
  {
    తిరిగి self.val.case_Ok;
  }
  లేకపోతే
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1184size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_5f_s { uint8_t దత్తాంశం[1184U]; } Eurydice_arr_5f;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_shared_5f2(స్థిరరాశి Eurydice_arr_5f *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_గమ్యం_shared_210(స్థిరరాశి Eurydice_arr_5f *a, కొలత_t r)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = r;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2400size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_7d_s { uint8_t దత్తాంశం[2400U]; } Eurydice_arr_7d;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d48(స్థిరరాశి Eurydice_arr_7d *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1152size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_0e_s { uint8_t దత్తాంశం[1152U]; } Eurydice_arr_0e;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1152
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_f4(స్థిరరాశి Eurydice_arr_0e *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1152U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d417(Eurydice_arr_7d *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1152
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_f4(Eurydice_arr_0e *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1152U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_mut_5f4(Eurydice_arr_5f *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d416(Eurydice_arr_5f *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 24
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_ed(స్థిరరాశి Eurydice_arr_94 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)24U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $384size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_b20_s { uint8_t దత్తాంశం[384U]; } Eurydice_arr_b20;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 384
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d415(Eurydice_arr_b20 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 384
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_a9(స్థిరరాశి Eurydice_arr_b20 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)384U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $32size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_ec_s { uint8_t దత్తాంశం[32U]; } Eurydice_arr_ec;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_ec, core_array_TryFromSliceError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_07_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  సంఘం {
    Eurydice_arr_ec case_Ok;
    core_array_Try_From_ముక్క_Error case_Err;
  }
  val;
}
core_ఫలితం_ఫలితం_07;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$32size_t]], core_array_TryFromSliceError

*/
స్థిర అంతఃవరుస Eurydice_arr_ec core_ఫలితం_unwrap_26_39(core_ఫలితం_ఫలితం_07 self)
{
  ఒకవేళ (self.ట్యాగ్ == core_ఫలితం_Ok)
  {
    తిరిగి self.val.case_Ok;
  }
  లేకపోతే
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $64size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_c7_s { uint8_t దత్తాంశం[64U]; } Eurydice_arr_c7;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_shared_5f1(స్థిరరాశి Eurydice_arr_c7 *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d47(స్థిరరాశి Eurydice_arr_c7 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1184
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_ff(స్థిరరాశి Eurydice_arr_5f *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1184U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1088size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_2b_s { uint8_t దత్తాంశం[1088U]; } Eurydice_arr_2b;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_mut_5f3(Eurydice_arr_2b *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d414(Eurydice_arr_2b *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 20
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_8f(స్థిరరాశి Eurydice_arr_fc *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)20U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $320size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_b0_s { uint8_t దత్తాంశం[320U]; } Eurydice_arr_b0;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 320
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d413(Eurydice_arr_b0 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 320
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_56(స్థిరరాశి Eurydice_arr_b0 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)320U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $256size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_04_s { int16_t దత్తాంశం[256U]; } Eurydice_arr_04;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int16_t
with const generics
- N= 256
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_i16
Eurydice_array_గమ్యం_ముక్క_shared_99(స్థిరరాశి Eurydice_arr_04 *a)
{
  Eurydice_borrow_ముక్క_i16 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)256U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $128size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_89_s { uint8_t దత్తాంశం[128U]; } Eurydice_arr_89;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_89
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_58_s { Eurydice_arr_89 దత్తాంశం[3U]; } Eurydice_arr_58;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $33size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_fa0_s { uint8_t దత్తాంశం[33U]; } Eurydice_arr_fa0;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 33
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_b5(స్థిరరాశి Eurydice_arr_fa0 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)33U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_fa0
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_fd_s { Eurydice_arr_fa0 దత్తాంశం[3U]; } Eurydice_arr_fd;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 33
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d412(Eurydice_arr_fa0 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $272size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_5b_s { int16_t దత్తాంశం[272U]; } Eurydice_arr_5b;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_i16
Eurydice_array_గమ్యం_subslice_shared_e70(స్థిరరాశి Eurydice_arr_5b *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_i16){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $168size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_c5_s { uint8_t దత్తాంశం[168U]; } Eurydice_arr_c5;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d46(స్థిరరాశి Eurydice_arr_c5 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_2c_s { Eurydice_arr_c5 దత్తాంశం[3U]; } Eurydice_arr_2c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_5b
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_b1_s { Eurydice_arr_5b దత్తాంశం[3U]; } Eurydice_arr_b1;

/**
A monomorphic instance of Eurydice.arr
with types size_t
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_eb_s { కొలత_t దత్తాంశం[3U]; } Eurydice_arr_eb;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_i16
Eurydice_array_గమ్యం_subslice_mut_e7(Eurydice_arr_5b *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_i16){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $504size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_79_s { uint8_t దత్తాంశం[504U]; } Eurydice_arr_79;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 504
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d45(స్థిరరాశి Eurydice_arr_79 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_79
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_7e_s { Eurydice_arr_79 దత్తాంశం[3U]; } Eurydice_arr_7e;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 504
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_48(Eurydice_arr_79 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)504U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $34size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_31_s { uint8_t దత్తాంశం[34U]; } Eurydice_arr_31;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_31
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_810_s { Eurydice_arr_31 దత్తాంశం[3U]; } Eurydice_arr_810;

/**
A monomorphic instance of Eurydice.slice_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t

*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_ముక్క_subslice_from_shared_6d(Eurydice_borrow_ముక్క_u8 s, కొలత_t r)
{
  తిరిగి (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = s.ptr + r, .meta = s.meta - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1120size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_af_s { uint8_t దత్తాంశం[1120U]; } Eurydice_arr_af;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1120
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_81(స్థిరరాశి Eurydice_arr_af *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1120U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1088
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_06(స్థిరరాశి Eurydice_arr_2b *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1088U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_mut_5f2(Eurydice_arr_af *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)1120U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d411(Eurydice_arr_af *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_mut_5f1(Eurydice_arr_c7 *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d410(Eurydice_arr_c7 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_shared_5f0(స్థిరరాశి Eurydice_arr_2b *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d44(స్థిరరాశి Eurydice_arr_2b *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2400
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_51(స్థిరరాశి Eurydice_arr_7d *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)2400U;
  తిరిగి lit;
}

రకనిర్వచనం నిర్మాణం int16_t_x2_s
{
  int16_t fst;
  int16_t snd;
}
int16_t_x2;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$24size_t]]

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_94
libcrux_secrets_int_ప్రజా_integers_declassify_d8_40(Eurydice_arr_94 self)
{
  తిరిగి self;
}

రకనిర్వచనం నిర్మాణం uint8_t_x3_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
}
uint8_t_x3;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$20size_t]]

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_fc
libcrux_secrets_int_ప్రజా_integers_declassify_d8_2b(Eurydice_arr_fc self)
{
  తిరిగి self;
}

రకనిర్వచనం నిర్మాణం uint8_t_x5_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
  uint8_t f3;
  uint8_t f4;
}
uint8_t_x5;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$8size_t]]

*/
స్థిర KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_secrets_int_ప్రజా_integers_declassify_d8_52(Eurydice_array_u8x8 self)
{
  తిరిగి self;
}

రకనిర్వచనం నిర్మాణం uint8_t_x4_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
  uint8_t f3;
}
uint8_t_x4;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$2size_t]]

*/
స్థిర KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_secrets_int_ప్రజా_integers_declassify_d8_75(Eurydice_array_u8x2 self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types Eurydice_arr int16_t[[$16size_t]]

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_secrets_int_ప్రజా_integers_classify_27_4b(Eurydice_arr_d6 self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a ([T])> for &'a ([T])}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_6d
with types uint8_t

*/
స్థిర KRML_MUSTINLINE Eurydice_borrow_ముక్క_u8
libcrux_secrets_int_classify_ప్రజా_classify_ref_6d_90(Eurydice_borrow_ముక్క_u8 self)
{
  తిరిగి self;
}

రకనిర్వచనం నిర్మాణం int16_t_x8_s
{
  int16_t fst;
  int16_t snd;
  int16_t thd;
  int16_t f3;
  int16_t f4;
  int16_t f5;
  int16_t f6;
  int16_t f7;
}
int16_t_x8;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 16
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_i16
Eurydice_array_గమ్యం_subslice_shared_e7(స్థిరరాశి Eurydice_arr_d6 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_i16){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a ([T])> for &'a ([T])}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_6d
with types int16_t

*/
స్థిర KRML_MUSTINLINE Eurydice_borrow_ముక్క_i16
libcrux_secrets_int_classify_ప్రజా_classify_ref_6d_39(Eurydice_borrow_ముక్క_i16 self)
{
  తిరిగి self;
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_i16
Eurydice_ముక్క_subslice_shared_a6(Eurydice_borrow_ముక్క_i16 s, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_i16){ .ptr = s.ptr + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_d6, core_array_TryFromSliceError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_ec_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  సంఘం {
    Eurydice_arr_d6 case_Ok;
    core_array_Try_From_ముక్క_Error case_Err;
  }
  val;
}
core_ఫలితం_ఫలితం_ec;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr int16_t[[$16size_t]], core_array_TryFromSliceError

*/
స్థిర అంతఃవరుస Eurydice_arr_d6 core_ఫలితం_unwrap_26_d3(core_ఫలితం_ఫలితం_ec self)
{
  ఒకవేళ (self.ట్యాగ్ == core_ఫలితం_Ok)
  {
    తిరిగి self.val.case_Ok;
  }
  లేకపోతే
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $128size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_34_s { int16_t దత్తాంశం[128U]; } Eurydice_arr_34;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d43(స్థిరరాశి Eurydice_arr_94 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d49(Eurydice_arr_94 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 16
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_29(Eurydice_arr_b2 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)16U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d42(స్థిరరాశి Eurydice_arr_b2 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d48(Eurydice_arr_b2 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $19size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_38_s { uint8_t దత్తాంశం[19U]; } Eurydice_arr_38;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d41(స్థిరరాశి Eurydice_arr_38 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d47(Eurydice_arr_38 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types int32_t, size_t

*/
రకనిర్వచనం నిర్మాణం Eurydice_dst_ref_mut_83_s
{
  int32_t *ptr;
  కొలత_t meta;
}
Eurydice_dst_ref_mut_83;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_83
Eurydice_ముక్క_subslice_mut_47(Eurydice_dst_ref_mut_83 s, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = s.ptr + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 16
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_29(స్థిరరాశి Eurydice_arr_b2 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)16U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_b2
with const generics
- $16size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_a30_s { Eurydice_arr_b2 దత్తాంశం[16U]; } Eurydice_arr_a30;

/**
A monomorphic instance of Eurydice.array_to_subslice_to_mut
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_గమ్యం_mut_21(Eurydice_arr_ec *a, కొలత_t r)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = r;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4627size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_93_s { uint8_t దత్తాంశం[4627U]; } Eurydice_arr_93;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4627
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_11(స్థిరరాశి Eurydice_arr_93 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4627U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2592size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_43_s { uint8_t దత్తాంశం[2592U]; } Eurydice_arr_43;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2592
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_fc(స్థిరరాశి Eurydice_arr_43 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)2592U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4896size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_e2_s { uint8_t దత్తాంశం[4896U]; } Eurydice_arr_e2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4896
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_f7(స్థిరరాశి Eurydice_arr_e2 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4896U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $256size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_6c_s { int32_t దత్తాంశం[256U]; } Eurydice_arr_6c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $8size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_81_s { Eurydice_arr_6c దత్తాంశం[8U]; } Eurydice_arr_81;

#నిర్వచించు core_option_None 0
#నిర్వచించు core_option_Some 1

రకనిర్వచనం uint8_t core_option_Option_45_ట్యాగులు;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_81

*/
రకనిర్వచనం నిర్మాణం core_option_Option_45_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_81 f0;
}
core_option_Option_45;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_c7

*/
రకనిర్వచనం నిర్మాణం core_option_Option_b2_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_c7 f0;
}
core_option_Option_b2;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4627
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_11(Eurydice_arr_93 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4627U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_6c, size_t

*/
రకనిర్వచనం నిర్మాణం Eurydice_dst_ref_shared_20_s
{
  స్థిరరాశి Eurydice_arr_6c *ptr;
  కొలత_t meta;
}
Eurydice_dst_ref_shared_20;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_20
Eurydice_array_గమ్యం_ముక్క_shared_861(స్థిరరాశి Eurydice_arr_81 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)8U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_6c, size_t

*/
రకనిర్వచనం నిర్మాణం Eurydice_dst_ref_mut_20_s
{
  Eurydice_arr_6c *ptr;
  కొలత_t meta;
}
Eurydice_dst_ref_mut_20;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_20 Eurydice_array_గమ్యం_ముక్క_mut_861(Eurydice_arr_81 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)8U;
  తిరిగి lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$64size_t]]

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_secrets_mem_అభ్యర్థనలు_ct_declassify_56(స్థిరరాశి Eurydice_arr_c7 *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1024size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_1b_s { uint8_t దత్తాంశం[1024U]; } Eurydice_arr_1b;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1024
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_68(స్థిరరాశి Eurydice_arr_1b *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1024U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1024
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_68(Eurydice_arr_1b *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1024U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2592
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_fc(Eurydice_arr_43 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)2592U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4896
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_f7(Eurydice_arr_e2 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4896U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $3309size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_0c_s { uint8_t దత్తాంశం[3309U]; } Eurydice_arr_0c;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 3309
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_6b(స్థిరరాశి Eurydice_arr_0c *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)3309U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1952size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_29_s { uint8_t దత్తాంశం[1952U]; } Eurydice_arr_29;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1952
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_37(స్థిరరాశి Eurydice_arr_29 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1952U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4032size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_24_s { uint8_t దత్తాంశం[4032U]; } Eurydice_arr_24;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4032
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_98(స్థిరరాశి Eurydice_arr_24 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4032U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $6size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_5d0_s { Eurydice_arr_6c దత్తాంశం[6U]; } Eurydice_arr_5d0;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_5d0

*/
రకనిర్వచనం నిర్మాణం core_option_Option_05_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_5d0 f0;
}
core_option_Option_05;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $48size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_65_s { uint8_t దత్తాంశం[48U]; } Eurydice_arr_65;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_65

*/
రకనిర్వచనం నిర్మాణం core_option_Option_81_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_65 f0;
}
core_option_Option_81;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 3309
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_6b(Eurydice_arr_0c *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)3309U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_20
Eurydice_array_గమ్యం_ముక్క_shared_860(స్థిరరాశి Eurydice_arr_5d0 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)6U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_20 Eurydice_array_గమ్యం_ముక్క_mut_860(Eurydice_arr_5d0 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)6U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 48
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_9f0(స్థిరరాశి Eurydice_arr_65 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)48U;
  తిరిగి lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$48size_t]]

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_secrets_mem_అభ్యర్థనలు_ct_declassify_69(స్థిరరాశి Eurydice_arr_65 *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1952
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_37(Eurydice_arr_29 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1952U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4032
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_98(Eurydice_arr_24 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4032U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2420size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_85_s { uint8_t దత్తాంశం[2420U]; } Eurydice_arr_85;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2420
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_0d(స్థిరరాశి Eurydice_arr_85 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)2420U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1312size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_02_s { uint8_t దత్తాంశం[1312U]; } Eurydice_arr_02;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1312
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_9f(స్థిరరాశి Eurydice_arr_02 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1312U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2560size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_10_s { uint8_t దత్తాంశం[2560U]; } Eurydice_arr_10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2560
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_34(స్థిరరాశి Eurydice_arr_10 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)2560U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $4size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_b7_s { Eurydice_arr_6c దత్తాంశం[4U]; } Eurydice_arr_b7;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_b7

*/
రకనిర్వచనం నిర్మాణం core_option_Option_51_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_b7 f0;
}
core_option_Option_51;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_ec

*/
రకనిర్వచనం నిర్మాణం core_option_Option_14_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_ec f0;
}
core_option_Option_14;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2420
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_0d(Eurydice_arr_85 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)2420U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 4
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_20
Eurydice_array_గమ్యం_ముక్క_shared_86(స్థిరరాశి Eurydice_arr_b7 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 4
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_20 Eurydice_array_గమ్యం_ముక్క_mut_86(Eurydice_arr_b7 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 256
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_83
Eurydice_array_గమ్యం_subslice_mut_44(Eurydice_arr_6c *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types int32_t, size_t

*/
రకనిర్వచనం నిర్మాణం Eurydice_dst_ref_shared_83_s
{
  స్థిరరాశి int32_t *ptr;
  కొలత_t meta;
}
Eurydice_dst_ref_shared_83;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 256
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_83
Eurydice_array_గమ్యం_ముక్క_shared_af(స్థిరరాశి Eurydice_arr_6c *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)256U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $136size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_ff_s { uint8_t దత్తాంశం[136U]; } Eurydice_arr_ff;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_shared_5f(స్థిరరాశి Eurydice_arr_ff *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d40(స్థిరరాశి Eurydice_arr_ff *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$32size_t]]

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_secrets_mem_అభ్యర్థనలు_ct_declassify_4b(స్థిరరాశి Eurydice_arr_ec *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $768size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_d2_s { uint8_t దత్తాంశం[768U]; } Eurydice_arr_d2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 768
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_27(స్థిరరాశి Eurydice_arr_d2 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)768U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 768
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_27(Eurydice_arr_d2 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)768U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $640size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_20_s { uint8_t దత్తాంశం[640U]; } Eurydice_arr_20;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 640
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_4f(స్థిరరాశి Eurydice_arr_20 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)640U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 640
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_4f(Eurydice_arr_20 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)640U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $576size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_220_s { uint8_t దత్తాంశం[576U]; } Eurydice_arr_220;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 576
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_8a(స్థిరరాశి Eurydice_arr_220 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)576U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 576
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_8a(Eurydice_arr_220 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)576U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $11size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_c9_s { uint8_t దత్తాంశం[11U]; } Eurydice_arr_c9;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 11
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_2f(స్థిరరాశి Eurydice_arr_c9 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)11U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_82_s { uint8_t దత్తాంశం[1U]; } Eurydice_arr_82;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_79(స్థిరరాశి Eurydice_arr_82 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1U;
  తిరిగి lit;
}

/**
 Mark memory as secret.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_classify
with types Eurydice_derefed_slice uint8_t

*/
స్థిర KRML_MUSTINLINE శూన్య libcrux_secrets_mem_అభ్యర్థనలు_ct_classify_45(స్థిరరాశి uint8_t (*val)[])
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1312
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_9f0(Eurydice_arr_02 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)1312U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2560
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_34(Eurydice_arr_10 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)2560U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 64
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_17(స్థిరరాశి Eurydice_arr_c7 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)64U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $263size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_d0_s { int32_t దత్తాంశం[263U]; } Eurydice_arr_d0;

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_d0, size_t

*/
రకనిర్వచనం నిర్మాణం Eurydice_dst_ref_mut_33_s
{
  Eurydice_arr_d0 *ptr;
  కొలత_t meta;
}
Eurydice_dst_ref_mut_33;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_d0
with const generics
- $4size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_930_s { Eurydice_arr_d0 దత్తాంశం[4U]; } Eurydice_arr_930;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$263size_t]]
with const generics
- N= 4
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_33 Eurydice_array_గమ్యం_ముక్క_mut_7e(Eurydice_arr_930 *a)
{
  Eurydice_dst_ref_mut_33 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_d0, size_t

*/
రకనిర్వచనం నిర్మాణం Eurydice_dst_ref_shared_33_s
{
  స్థిరరాశి Eurydice_arr_d0 *ptr;
  కొలత_t meta;
}
Eurydice_dst_ref_shared_33;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $840size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_d10_s { uint8_t దత్తాంశం[840U]; } Eurydice_arr_d10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 840
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_4c(స్థిరరాశి Eurydice_arr_d10 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)840U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 34
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_e9(స్థిరరాశి Eurydice_arr_31 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)34U;
  తిరిగి lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_derefed_slice uint8_t

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_secrets_mem_అభ్యర్థనలు_ct_declassify_45(స్థిరరాశి uint8_t (*val)[])
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 263
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_83
Eurydice_array_గమ్యం_ముక్క_shared_2c0(స్థిరరాశి Eurydice_arr_d0 *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)263U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types int32_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 263
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_83
Eurydice_array_గమ్యం_subslice_from_mut_11(Eurydice_arr_d0 *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)263U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $66size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_91_s { uint8_t దత్తాంశం[66U]; } Eurydice_arr_91;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 66
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_f1(స్థిరరాశి Eurydice_arr_91 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)66U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 128
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_78(స్థిరరాశి Eurydice_arr_89 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)128U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 128
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_78(Eurydice_arr_89 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)128U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_82(స్థిరరాశి Eurydice_array_u8x2 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)2U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 32
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_01(స్థిరరాశి Eurydice_arr_ec *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)32U;
  తిరిగి lit;
}

/**
 Mark memory as secret.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_classify
with types Eurydice_arr uint8_t[[$32size_t]]

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_secrets_mem_అభ్యర్థనలు_ct_classify_4b(స్థిరరాశి Eurydice_arr_ec *val)
{

}

రకనిర్వచనం నిర్మాణం Eurydice_arr_c5_x4_s
{
  Eurydice_arr_c5 fst;
  Eurydice_arr_c5 snd;
  Eurydice_arr_c5 thd;
  Eurydice_arr_c5 f3;
}
Eurydice_arr_c5_x4;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 168
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_2c(Eurydice_arr_c5 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)168U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 840
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_4c(Eurydice_arr_d10 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)840U;
  తిరిగి lit;
}

రకనిర్వచనం నిర్మాణం Eurydice_arr_ff_x4_s
{
  Eurydice_arr_ff fst;
  Eurydice_arr_ff snd;
  Eurydice_arr_ff thd;
  Eurydice_arr_ff f3;
}
Eurydice_arr_ff_x4;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 136
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_58(Eurydice_arr_ff *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)136U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_shared_d4(స్థిరరాశి Eurydice_arr_ec *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_ff
with const generics
- $4size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_dc0_s { Eurydice_arr_ff దత్తాంశం[4U]; } Eurydice_arr_dc0;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $4size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_9c_s { Eurydice_arr_c5 దత్తాంశం[4U]; } Eurydice_arr_9c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $4size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_68_s { Eurydice_borrow_ముక్క_u8 దత్తాంశం[4U]; } Eurydice_arr_68;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d46(Eurydice_arr_ec *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_mut_5f0(Eurydice_arr_c5 *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)168U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $1size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_88_s { Eurydice_arr_c5 దత్తాంశం[1U]; } Eurydice_arr_88;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 64
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_17(Eurydice_arr_c7 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)64U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 48
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_9f(Eurydice_arr_65 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)48U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 32
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_01(Eurydice_arr_ec *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)32U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $28size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_a2_s { uint8_t దత్తాంశం[28U]; } Eurydice_arr_a2;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 28
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8 Eurydice_array_గమ్యం_ముక్క_mut_5e(Eurydice_arr_a2 *a)
{
  Eurydice_mut_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)28U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $104size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_c4_s { uint8_t దత్తాంశం[104U]; } Eurydice_arr_c4;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 104
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_72(స్థిరరాశి Eurydice_arr_c4 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)104U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 104
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d45(Eurydice_arr_c4 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $144size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_f4_s { uint8_t దత్తాంశం[144U]; } Eurydice_arr_f4;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 144
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_38(స్థిరరాశి Eurydice_arr_f4 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)144U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 144
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d44(Eurydice_arr_f4 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $72size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_ab_s { uint8_t దత్తాంశం[72U]; } Eurydice_arr_ab;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 72
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_e2(స్థిరరాశి Eurydice_arr_ab *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)72U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 72
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d43(Eurydice_arr_ab *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.slice_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t

*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_ముక్క_subslice_గమ్యం_shared_72(Eurydice_borrow_ముక్క_u8 s, కొలత_t r)
{
  తిరిగి (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = s.ptr, .meta = r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_from_mut_5f(Eurydice_arr_ff *a, కొలత_t r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){ .ptr = a->దత్తాంశం + r, .meta = (కొలత_t)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_గమ్యం_shared_21(స్థిరరాశి Eurydice_array_u8x8 *a, కొలత_t r)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = r;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_6e(స్థిరరాశి Eurydice_array_u8x8 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)8U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_ముక్క_subslice_mut_c8(Eurydice_mut_borrow_ముక్క_u8 s, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){ .ptr = s.ptr + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 136
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_58(స్థిరరాశి Eurydice_arr_ff *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)136U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d42(Eurydice_arr_ff *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $5size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_84_s { uint64_t దత్తాంశం[5U]; } Eurydice_arr_84;

రకనిర్వచనం నిర్మాణం కొలత_t_x2_s
{
  కొలత_t fst;
  కొలత_t snd;
}
కొలత_t_x2;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $1size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_dc_s { Eurydice_borrow_ముక్క_u8 దత్తాంశం[1U]; } Eurydice_arr_dc;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 168
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_array_గమ్యం_ముక్క_shared_2c(స్థిరరాశి Eurydice_arr_c5 *a)
{
  Eurydice_borrow_ముక్క_u8 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)168U;
  తిరిగి lit;
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_array_u8x8, core_array_TryFromSliceError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_8e_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  సంఘం {
    Eurydice_array_u8x8 case_Ok;
    core_array_Try_From_ముక్క_Error case_Err;
  }
  val;
}
core_ఫలితం_ఫలితం_8e;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$8size_t]], core_array_TryFromSliceError

*/
స్థిర అంతఃవరుస Eurydice_array_u8x8 core_ఫలితం_unwrap_26_e0(core_ఫలితం_ఫలితం_8e self)
{
  ఒకవేళ (self.ట్యాగ్ == core_ఫలితం_Ok)
  {
    తిరిగి self.val.case_Ok;
  }
  లేకపోతే
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d41(Eurydice_arr_c5 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $24size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_22_s { uint64_t దత్తాంశం[24U]; } Eurydice_arr_22;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_ff
with const generics
- $1size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_0b_s { Eurydice_arr_ff దత్తాంశం[1U]; } Eurydice_arr_0b;

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $25size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_7c_s { uint64_t దత్తాంశం[25U]; } Eurydice_arr_7c;

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
Eurydice_ముక్క_subslice_shared_c8(Eurydice_borrow_ముక్క_u8 s, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){ .ptr = s.ptr + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $8size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_4d_s { int32_t దత్తాంశం[8U]; } Eurydice_arr_4d;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_83
Eurydice_array_గమ్యం_subslice_shared_44(స్థిరరాశి Eurydice_arr_4d *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_83){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం }
    );
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types bool

*/
స్థిర KRML_MUSTINLINE శూన్య libcrux_secrets_mem_అభ్యర్థనలు_ct_declassify_5f(స్థిరరాశి bool *val)
{

}

రకనిర్వచనం నిర్మాణం int32_t_x2_s
{
  int32_t fst;
  int32_t snd;
}
int32_t_x2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_83
Eurydice_array_గమ్యం_ముక్క_shared_fd(స్థిరరాశి Eurydice_arr_4d *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)8U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_83
Eurydice_ముక్క_subslice_shared_47(Eurydice_dst_ref_shared_83 s, core_ops_range_Range_87 r)
{
  తిరిగి
    (KRML_CLITERAL(Eurydice_dst_ref_shared_83){ .ptr = s.ptr + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం });
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types int32_t
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_83 Eurydice_array_గమ్యం_ముక్క_mut_fd(Eurydice_arr_4d *a)
{
  Eurydice_dst_ref_mut_83 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)8U;
  తిరిగి lit;
}

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_c9

*/
రకనిర్వచనం నిర్మాణం core_option_Option_57_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_c9 f0;
}
core_option_Option_57;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 34
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d40(Eurydice_arr_31 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

రకనిర్వచనం నిర్మాణం uint8_t_x2_s
{
  uint8_t fst;
  uint8_t snd;
}
uint8_t_x2;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 66
*/
స్థిర అంతఃవరుస Eurydice_mut_borrow_ముక్క_u8
Eurydice_array_గమ్యం_subslice_mut_d4(Eurydice_arr_91 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ముక్క_u8){
        .ptr = a->దత్తాంశం + r.ప్రారంభం,
        .meta = r.చివర - r.ప్రారంభం
      }
    );
}

రకనిర్వచనం నిర్మాణం libcrux_ml_kem_utils_extraction_helper_Keypair768_s
{
  Eurydice_arr_0e fst;
  Eurydice_arr_5f snd;
}
libcrux_ml_kem_utils_extraction_helper_Keypair768;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint64_t

*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_secrets_int_ప్రజా_integers_declassify_d8_49(uint64_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint32_t

*/
స్థిర KRML_MUSTINLINE uint32_t
libcrux_secrets_int_ప్రజా_integers_classify_27_df(uint32_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint64_t

*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_secrets_int_ప్రజా_integers_classify_27_49(uint64_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint16_t

*/
స్థిర KRML_MUSTINLINE uint16_t
libcrux_secrets_int_ప్రజా_integers_declassify_d8_de(uint16_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint16_t

*/
స్థిర KRML_MUSTINLINE uint16_t
libcrux_secrets_int_ప్రజా_integers_classify_27_de(uint16_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint32_t

*/
స్థిర KRML_MUSTINLINE uint32_t
libcrux_secrets_int_ప్రజా_integers_declassify_d8_df(uint32_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int32_t

*/
స్థిర KRML_MUSTINLINE int32_t
libcrux_secrets_int_ప్రజా_integers_declassify_d8_a8(int32_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int32_t

*/
స్థిర KRML_MUSTINLINE int32_t libcrux_secrets_int_ప్రజా_integers_classify_27_a8(int32_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint8_t

*/
స్థిర KRML_MUSTINLINE uint8_t
libcrux_secrets_int_ప్రజా_integers_declassify_d8_90(uint8_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int16_t

*/
స్థిర KRML_MUSTINLINE int16_t libcrux_secrets_int_ప్రజా_integers_classify_27_39(int16_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int16_t

*/
స్థిర KRML_MUSTINLINE int16_t
libcrux_secrets_int_ప్రజా_integers_declassify_d8_39(int16_t self)
{
  తిరిగి self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint8_t

*/
స్థిర KRML_MUSTINLINE uint8_t libcrux_secrets_int_ప్రజా_integers_classify_27_90(uint8_t self)
{
  తిరిగి self;
}

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు combined_core_H_DEFINED
#అయితే_ముగింపు /* combined_core_H */

/* from libcrux/combined_extraction/generated/libcrux_sha3_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే libcrux_sha3_portable_H
#నిర్వచించు libcrux_sha3_portable_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


/**
A monomorphic instance of libcrux_sha3.generic_keccak.KeccakState
with types uint64_t
with const generics
- $1size_t
*/
రకనిర్వచనం Eurydice_arr_7c libcrux_sha3_generic_keccak_KeccakState_f3;

రకనిర్వచనం libcrux_sha3_generic_keccak_KeccakState_f3 libcrux_sha3_portable_KeccakState;

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $136size_t
*/
రకనిర్వచనం నిర్మాణం libcrux_sha3_generic_keccak_xof_KeccakXofState_8d_s
{
  Eurydice_arr_7c inner;
  Eurydice_arr_0b buf;
  కొలత_t buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_8d;

రకనిర్వచనం libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_portable_incremental_Shake256Xof;

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_zero_d2(శూన్య)
{
  తిరిగి 0ULL;
}

స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__veor5q_u64(
  uint64_t a,
  uint64_t b,
  uint64_t c,
  uint64_t d,
  uint64_t e
)
{
  తిరిగి (((a ^ b) ^ c) ^ d) ^ e;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor5_d2(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
  తిరిగి libcrux_sha3_simd_portable__veor5q_u64(a, b, c, d, e);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 1
- RIGHT= 63
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_76(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)1);
}

స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__vrax1q_u64(uint64_t a, uint64_t b)
{
  తిరిగి a ^ libcrux_sha3_simd_portable_rotate_ఎడమ_76(b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vrax1q_u64(a, b);
}

స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vbcaxq_u64(uint64_t a, uint64_t b, uint64_t c)
{
  తిరిగి a ^ (b & ~c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_and_not_xor_d2(uint64_t a, uint64_t b, uint64_t c)
{
  తిరిగి libcrux_sha3_simd_portable__vbcaxq_u64(a, b, c);
}

స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__veorq_n_u64(uint64_t a, uint64_t c)
{
  తిరిగి a ^ c;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_constant_d2(uint64_t a, uint64_t c)
{
  తిరిగి libcrux_sha3_simd_portable__veorq_n_u64(a, c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_xor_d2(uint64_t a, uint64_t b)
{
  తిరిగి a ^ b;
}

/**
 Create a new Shake128 x4 state.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.new_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_generic_keccak_new_80_71(శూన్య)
{
  Eurydice_arr_7c lit;
  uint64_t repeat_వ్యక్తీకరణ[25U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)25U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_sha3_simd_portable_zero_d2();
  }
  జ్ఞాపకం_నకలు(lit.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)25U * పరిమాణం (uint64_t));
  తిరిగి lit;
}

/**
 Create a new SHAKE-128 state object.
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_portable_incremental_shake128_init(శూన్య)
{
  తిరిగి libcrux_sha3_generic_keccak_new_80_71();
}

#నిర్వచించు LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS ((KRML_CLITERAL(Eurydice_arr_22){ .దత్తాంశం = { 1ULL, 32898ULL, 9223372036854808714ULL, 9223372039002292224ULL, 32907ULL, 2147483649ULL, 9223372039002292353ULL, 9223372036854808585ULL, 138ULL, 136ULL, 2147516425ULL, 2147483658ULL, 2147516555ULL, 9223372036854775947ULL, 9223372036854808713ULL, 9223372036854808579ULL, 9223372036854808578ULL, 9223372036854775936ULL, 32778ULL, 9223372039002259466ULL, 9223372039002292353ULL, 9223372036854808704ULL, 2147483649ULL, 9223372039002292232ULL } }))

/**
A monomorphic instance of libcrux_sha3.traits.get_ij
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE స్థిరరాశి
uint64_t
*libcrux_sha3_traits_get_ij_71(స్థిరరాశి Eurydice_arr_7c *arr, కొలత_t i, కొలత_t j)
{
  తిరిగి &arr->దత్తాంశం[(కొలత_t)5U * j + i];
}

/**
A monomorphic instance of libcrux_sha3.traits.set_ij
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_traits_సమితి_ij_71(Eurydice_arr_7c *arr, కొలత_t i, కొలత_t j, uint64_t విలువ)
{
  arr->దత్తాంశం[(కొలత_t)5U * j + i] = విలువ;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 168
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_60(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం
)
{
  Eurydice_arr_7c state_flat = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)168U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    కొలత_t స్థానభ్రంశం = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_array_u8x8 arr;
    జ్ఞాపకం_నకలు(arr.దత్తాంశం,
      Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = స్థానభ్రంశం, .చివర = స్థానభ్రంశం + (కొలత_t)8U })).ptr,
      (కొలత_t)8U * పరిమాణం (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ఫలితం_unwrap_26_e0((
          KRML_CLITERAL(core_ఫలితం_ఫలితం_8e){ .ట్యాగ్ = core_ఫలితం_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.దత్తాంశం[i0] = core_అంకె_u64_from_le_బైట్లు(uu____0);
  }
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)168U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    libcrux_sha3_traits_సమితి_ij_71(state,
      i0 / (కొలత_t)5U,
      i0 % (కొలత_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (కొలత_t)5U, i0 % (కొలత_t)5U)[0U] ^
        state_flat.దత్తాంశం[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 168
- DELIMITER= 31
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_37(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  Eurydice_arr_c5 బఫరు = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d41(&బఫరు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = len })),
    Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = ప్రారంభం, .చివర = ప్రారంభం + len })),
    uint8_t);
  బఫరు.దత్తాంశం[len] = 31U;
  కొలత_t uu____0 = (కొలత_t)168U - (కొలత_t)1U;
  బఫరు.దత్తాంశం[uu____0] = (uint32_t)బఫరు.దత్తాంశం[uu____0] | 128U;
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_60(state,
    Eurydice_array_గమ్యం_ముక్క_shared_2c(&బఫరు),
    (కొలత_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 168
- DELIMITER= 31
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_37(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_37(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం, len);
}

/**
 Get element `[i, j]`.
*/
/**
This function found in impl {core::ops::index::Index<(usize, usize), T> for libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.index_c2
with types uint64_t
with const generics
- N= 1
*/
స్థిర అంతఃవరుస స్థిరరాశి
uint64_t
*libcrux_sha3_generic_keccak_సూచీ_c2_71(స్థిరరాశి Eurydice_arr_7c *self, కొలత_t_x2 index)
{
  తిరిగి libcrux_sha3_traits_get_ij_71(self, index.fst, index.snd);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.theta_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_84
libcrux_sha3_generic_keccak_theta_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_84
  c =
    {
      .దత్తాంశం = {
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)0U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)0U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)0U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)0U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)0U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)1U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)1U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)1U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)1U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)1U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)2U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)2U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)2U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)2U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)2U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)3U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)3U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)3U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)3U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)3U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)4U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)4U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)4U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)4U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)4U }))[0U])
      }
    };
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_arr_84){
        .దత్తాంశం = {
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.దత్తాంశం[((కొలత_t)0U + (కొలత_t)4U) %
              (కొలత_t)5U],
            c.దత్తాంశం[((కొలత_t)0U + (కొలత_t)1U) % (కొలత_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.దత్తాంశం[((కొలత_t)1U + (కొలత_t)4U) %
              (కొలత_t)5U],
            c.దత్తాంశం[((కొలత_t)1U + (కొలత_t)1U) % (కొలత_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.దత్తాంశం[((కొలత_t)2U + (కొలత_t)4U) %
              (కొలత_t)5U],
            c.దత్తాంశం[((కొలత_t)2U + (కొలత_t)1U) % (కొలత_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.దత్తాంశం[((కొలత_t)3U + (కొలత_t)4U) %
              (కొలత_t)5U],
            c.దత్తాంశం[((కొలత_t)3U + (కొలత_t)1U) % (కొలత_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.దత్తాంశం[((కొలత_t)4U + (కొలత_t)4U) %
              (కొలత_t)5U],
            c.దత్తాంశం[((కొలత_t)4U + (కొలత_t)1U) % (కొలత_t)5U])
        }
      }
    );
}

/**
 Set element `[i, j] = v`.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.set_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_generic_keccak_సమితి_80_71(Eurydice_arr_7c *self, కొలత_t i, కొలత_t j, uint64_t v)
{
  libcrux_sha3_traits_సమితి_ij_71(self, i, j, v);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 36
- RIGHT= 28
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_02(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)36);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 36
- RIGHT= 28
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_02(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_02(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 36
- RIGHT= 28
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_02(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_02(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 3
- RIGHT= 61
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_ac(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)3);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 3
- RIGHT= 61
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ac(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_ac(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 3
- RIGHT= 61
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_ac(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 41
- RIGHT= 23
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_020(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)41);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 41
- RIGHT= 23
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_020(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_020(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 41
- RIGHT= 23
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_020(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_020(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 18
- RIGHT= 46
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_a9(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)18);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 18
- RIGHT= 46
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_a9(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_a9(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 18
- RIGHT= 46
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_a9(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_0_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_rho_0_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)0U,
    libcrux_sha3_simd_portable_xor_d2(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)0U }))[0U],
      t.దత్తాంశం[0U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_02(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)0U }))[0U],
      t.దత్తాంశం[0U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)0U }))[0U],
      t.దత్తాంశం[0U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_020(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)0U }))[0U],
      t.దత్తాంశం[0U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)0U }))[0U],
      t.దత్తాంశం[0U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 1
- RIGHT= 63
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_76(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_76(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 1
- RIGHT= 63
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_76(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_76(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 44
- RIGHT= 20
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_58(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)44);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 44
- RIGHT= 20
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_58(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_58(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 44
- RIGHT= 20
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_58(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_58(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 10
- RIGHT= 54
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_e0(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)10);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 10
- RIGHT= 54
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_e0(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_e0(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 10
- RIGHT= 54
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_e0(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 45
- RIGHT= 19
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_63(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)45);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 45
- RIGHT= 19
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_63(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_63(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 45
- RIGHT= 19
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_63(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_63(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 2
- RIGHT= 62
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_6a(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)2);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 2
- RIGHT= 62
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6a(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_6a(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 2
- RIGHT= 62
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_6a(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_1_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_rho_1_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_76(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)1U }))[0U],
      t.దత్తాంశం[1U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_58(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)1U }))[0U],
      t.దత్తాంశం[1U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)1U }))[0U],
      t.దత్తాంశం[1U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_63(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)1U }))[0U],
      t.దత్తాంశం[1U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)1U }))[0U],
      t.దత్తాంశం[1U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 62
- RIGHT= 2
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_ab(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)62);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 62
- RIGHT= 2
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ab(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_ab(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 62
- RIGHT= 2
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_ab(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 6
- RIGHT= 58
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_5b(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)6);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 6
- RIGHT= 58
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_5b(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_5b(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 6
- RIGHT= 58
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_5b(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 43
- RIGHT= 21
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_6f(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)43);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 43
- RIGHT= 21
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6f(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_6f(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 43
- RIGHT= 21
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_6f(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 15
- RIGHT= 49
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_62(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)15);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 15
- RIGHT= 49
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_62(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_62(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 15
- RIGHT= 49
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_62(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_62(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 61
- RIGHT= 3
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_23(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)61);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 61
- RIGHT= 3
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_23(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_23(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 61
- RIGHT= 3
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_23(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_23(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_2_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_rho_2_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)2U }))[0U],
      t.దత్తాంశం[2U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)2U }))[0U],
      t.దత్తాంశం[2U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)2U }))[0U],
      t.దత్తాంశం[2U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_62(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)2U }))[0U],
      t.దత్తాంశం[2U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_23(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)2U }))[0U],
      t.దత్తాంశం[2U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 28
- RIGHT= 36
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_37(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)28);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 28
- RIGHT= 36
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_37(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_37(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 28
- RIGHT= 36
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_37(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_37(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 55
- RIGHT= 9
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_bb(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)55);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 55
- RIGHT= 9
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_bb(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_bb(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 55
- RIGHT= 9
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_bb(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 25
- RIGHT= 39
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_b9(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)25);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 25
- RIGHT= 39
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_b9(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_b9(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 25
- RIGHT= 39
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_b9(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 21
- RIGHT= 43
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_54(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)21);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 21
- RIGHT= 43
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_54(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_54(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 21
- RIGHT= 43
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_54(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_54(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 56
- RIGHT= 8
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_4c(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)56);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 56
- RIGHT= 8
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_4c(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_4c(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 56
- RIGHT= 8
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_4c(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_3_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_rho_3_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_37(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)3U }))[0U],
      t.దత్తాంశం[3U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)3U }))[0U],
      t.దత్తాంశం[3U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)3U }))[0U],
      t.దత్తాంశం[3U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_54(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)3U }))[0U],
      t.దత్తాంశం[3U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)3U }))[0U],
      t.దత్తాంశం[3U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 27
- RIGHT= 37
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_ce(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)27);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 27
- RIGHT= 37
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ce(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_ce(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 27
- RIGHT= 37
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_ce(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 20
- RIGHT= 44
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_77(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)20);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 20
- RIGHT= 44
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_77(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_77(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 20
- RIGHT= 44
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_77(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_77(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 39
- RIGHT= 25
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_25(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)39);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 39
- RIGHT= 25
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_25(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_25(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 39
- RIGHT= 25
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_25(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_25(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 8
- RIGHT= 56
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_af(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)8);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 8
- RIGHT= 56
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_af(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_af(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 8
- RIGHT= 56
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_af(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_af(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 14
- RIGHT= 50
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ఎడమ_fd(uint64_t x)
{
  తిరిగి core_అంకె_u64_rotate_ఎడమ(x, (uint32_t)14);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 14
- RIGHT= 50
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_fd(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable_rotate_ఎడమ_fd(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 14
- RIGHT= 50
*/
స్థిర KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(uint64_t a, uint64_t b)
{
  తిరిగి libcrux_sha3_simd_portable__vxarq_u64_fd(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_4_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_rho_4_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)4U }))[0U],
      t.దత్తాంశం[4U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_77(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)4U }))[0U],
      t.దత్తాంశం[4U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_25(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)4U }))[0U],
      t.దత్తాంశం[4U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_af(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)4U }))[0U],
      t.దత్తాంశం[4U]));
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)4U }))[0U],
      t.దత్తాంశం[4U]));
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_rho_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_rho_0_80_71(self, t);
  libcrux_sha3_generic_keccak_rho_1_80_71(self, t);
  libcrux_sha3_generic_keccak_rho_2_80_71(self, t);
  libcrux_sha3_generic_keccak_rho_3_80_71(self, t);
  libcrux_sha3_generic_keccak_rho_4_80_71(self, t);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_0_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_pi_0_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)0U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)0U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)0U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)0U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)2U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_1_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_pi_1_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)1U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)1U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)1U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)1U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)1U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)1U, .snd = (కొలత_t)3U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_2_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_pi_2_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)2U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)2U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)2U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)2U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)2U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)2U, .snd = (కొలత_t)4U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_3_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_pi_3_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)3U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)3U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)3U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)3U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)3U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)3U, .snd = (కొలత_t)0U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_4_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_pi_4_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)4U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)1U,
    (కొలత_t)4U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)2U,
    (కొలత_t)4U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)3U,
    (కొలత_t)4U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)4U,
    (కొలత_t)4U,
    libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
      (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)4U, .snd = (కొలత_t)1U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య libcrux_sha3_generic_keccak_pi_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_7c old = self[0U];
  libcrux_sha3_generic_keccak_pi_0_80_71(self, old);
  libcrux_sha3_generic_keccak_pi_1_80_71(self, old);
  libcrux_sha3_generic_keccak_pi_2_80_71(self, old);
  libcrux_sha3_generic_keccak_pi_3_80_71(self, old);
  libcrux_sha3_generic_keccak_pi_4_80_71(self, old);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.chi_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య libcrux_sha3_generic_keccak_chi_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_7c old = self[0U];
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < (కొలత_t)5U; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)5U; i++)
    {
      కొలత_t j = i;
      libcrux_sha3_generic_keccak_సమితి_80_71(self,
        i1,
        j,
        libcrux_sha3_simd_portable_and_not_xor_d2(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = i1, .snd = j }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = i1, .snd = (j + (కొలత_t)2U) % (కొలత_t)5U }))[0U],
          libcrux_sha3_generic_keccak_సూచీ_c2_71(&old,
            (KRML_CLITERAL(కొలత_t_x2){ .fst = i1, .snd = (j + (కొలత_t)1U) % (కొలత_t)5U }))[0U]));
    }
  }
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.iota_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_iota_80_71(Eurydice_arr_7c *self, కొలత_t i)
{
  libcrux_sha3_generic_keccak_సమితి_80_71(self,
    (కొలత_t)0U,
    (కొలత_t)0U,
    libcrux_sha3_simd_portable_xor_constant_d2(libcrux_sha3_generic_keccak_సూచీ_c2_71(self,
        (KRML_CLITERAL(కొలత_t_x2){ .fst = (కొలత_t)0U, .snd = (కొలత_t)0U }))[0U],
      LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS.దత్తాంశం[i]));
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.keccakf1600_80
with types uint64_t
with const generics
- N= 1
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_keccakf1600_80_71(Eurydice_arr_7c *self)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)24U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_84 t = libcrux_sha3_generic_keccak_theta_80_71(self);
    libcrux_sha3_generic_keccak_rho_80_71(self, t);
    libcrux_sha3_generic_keccak_pi_80_71(self);
    libcrux_sha3_generic_keccak_chi_80_71(self);
    libcrux_sha3_generic_keccak_iota_80_71(self, i0);
  }
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 168
- DELIM= 31
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_final_80_bd(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_37(self, ఆదానం, ప్రారంభం, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
 Absorb
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_incremental_shake128_absorb_final(
  Eurydice_arr_7c *s,
  Eurydice_borrow_ముక్క_u8 data0
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { data0 } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd(s, &lvalue, (కొలత_t)0U, data0.meta);
}

/**
 Create a new SHAKE-256 state object.
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_portable_incremental_shake256_init(శూన్య)
{
  తిరిగి libcrux_sha3_generic_keccak_new_80_71();
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 136
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_b2(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం
)
{
  Eurydice_arr_7c state_flat = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)136U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    కొలత_t స్థానభ్రంశం = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_array_u8x8 arr;
    జ్ఞాపకం_నకలు(arr.దత్తాంశం,
      Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = స్థానభ్రంశం, .చివర = స్థానభ్రంశం + (కొలత_t)8U })).ptr,
      (కొలత_t)8U * పరిమాణం (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ఫలితం_unwrap_26_e0((
          KRML_CLITERAL(core_ఫలితం_ఫలితం_8e){ .ట్యాగ్ = core_ఫలితం_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.దత్తాంశం[i0] = core_అంకె_u64_from_le_బైట్లు(uu____0);
  }
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)136U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    libcrux_sha3_traits_సమితి_ij_71(state,
      i0 / (కొలత_t)5U,
      i0 % (కొలత_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (కొలత_t)5U, i0 % (కొలత_t)5U)[0U] ^
        state_flat.దత్తాంశం[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 31
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_22(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  Eurydice_arr_ff బఫరు = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d42(&బఫరు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = len })),
    Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = ప్రారంభం, .చివర = ప్రారంభం + len })),
    uint8_t);
  బఫరు.దత్తాంశం[len] = 31U;
  కొలత_t uu____0 = (కొలత_t)136U - (కొలత_t)1U;
  బఫరు.దత్తాంశం[uu____0] = (uint32_t)బఫరు.దత్తాంశం[uu____0] | 128U;
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_b2(state,
    Eurydice_array_గమ్యం_ముక్క_shared_58(&బఫరు),
    (కొలత_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 136
- DELIMITER= 31
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_22(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_22(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 136
- DELIM= 31
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_final_80_bd0(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_22(self, ఆదానం, ప్రారంభం, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
 Absorb some data for SHAKE-256 for the last time
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_incremental_shake256_absorb_final(
  Eurydice_arr_7c *s,
  Eurydice_borrow_ముక్క_u8 దత్తాంశం
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { దత్తాంశం } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd0(s, &lvalue, (కొలత_t)0U, దత్తాంశం.meta);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 168
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_60(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_60(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 168
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_ఖండం_80_e9(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_60(self, ఆదానం, ప్రారంభం);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 168
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_store_ఖండం_60(
  స్థిరరాశి Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  కొలత_t octets = len / (కొలత_t)8U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < octets; i++)
  {
    కొలత_t i0 = i;
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          i0 / (కొలత_t)5U,
          i0 % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + (కొలత_t)8U })),
      Eurydice_array_గమ్యం_ముక్క_shared_6e(&బైట్లు),
      uint8_t);
  }
  కొలత_t మిగిలిన = len % (కొలత_t)8U;
  ఒకవేళ (మిగిలిన > (కొలత_t)0U)
  {
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          octets / (కొలత_t)5U,
          octets % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + len - మిగిలిన;
    Eurydice_mut_borrow_ముక్క_u8
    uu____0 =
      Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + మిగిలిన }));
    Eurydice_ముక్క_copy(uu____0,
      Eurydice_array_గమ్యం_subslice_గమ్యం_shared_21(&బైట్లు, మిగిలిన),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 168
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_squeeze_9b_60(
  స్థిరరాశి Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_store_ఖండం_60(self, బహిర్గతం, ప్రారంభం, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 168
- DELIM= 31
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_generic_keccak_portable_keccak1_37(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_mut_borrow_ముక్క_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  కొలత_t ఆదానం_len = ఆదానం.meta;
  కొలత_t ఆదానం_ఖండాలు = ఆదానం_len / (కొలత_t)168U;
  కొలత_t ఆదానం_rem = ఆదానం_len % (కొలత_t)168U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < ఆదానం_ఖండాలు; i++)
  {
    కొలత_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
    libcrux_sha3_generic_keccak_absorb_ఖండం_80_e9(&s, &lvalue, i0 * (కొలత_t)168U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd(&s, &lvalue, ఆదానం_len - ఆదానం_rem, ఆదానం_rem);
  కొలత_t output_len = output.meta;
  కొలత_t output_ఖండాలు = output_len / (కొలత_t)168U;
  కొలత_t output_rem = output_len % (కొలత_t)168U;
  ఒకవేళ (output_ఖండాలు == (కొలత_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, (కొలత_t)0U, output_len);
  }
  లేకపోతే
  {
    libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, (కొలత_t)0U, (కొలత_t)168U);
    కొరకు (కొలత_t i = (కొలత_t)1U; i < output_ఖండాలు; i++)
    {
      కొలత_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, i0 * (కొలత_t)168U, (కొలత_t)168U);
    }
    ఒకవేళ (output_rem != (కొలత_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE128 implementation.
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_shake128(
  Eurydice_mut_borrow_ముక్క_u8 digest,
  Eurydice_borrow_ముక్క_u8 దత్తాంశం
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_37(దత్తాంశం, digest);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 136
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_b2(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_b2(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 136
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_ఖండం_80_e90(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_b2(self, ఆదానం, ప్రారంభం);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 136
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_store_ఖండం_b2(
  స్థిరరాశి Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  కొలత_t octets = len / (కొలత_t)8U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < octets; i++)
  {
    కొలత_t i0 = i;
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          i0 / (కొలత_t)5U,
          i0 % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + (కొలత_t)8U })),
      Eurydice_array_గమ్యం_ముక్క_shared_6e(&బైట్లు),
      uint8_t);
  }
  కొలత_t మిగిలిన = len % (కొలత_t)8U;
  ఒకవేళ (మిగిలిన > (కొలత_t)0U)
  {
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          octets / (కొలత_t)5U,
          octets % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + len - మిగిలిన;
    Eurydice_mut_borrow_ముక్క_u8
    uu____0 =
      Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + మిగిలిన }));
    Eurydice_ముక్క_copy(uu____0,
      Eurydice_array_గమ్యం_subslice_గమ్యం_shared_21(&బైట్లు, మిగిలిన),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 136
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_squeeze_9b_b2(
  స్థిరరాశి Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_store_ఖండం_b2(self, బహిర్గతం, ప్రారంభం, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 31
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_generic_keccak_portable_keccak1_22(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_mut_borrow_ముక్క_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  కొలత_t ఆదానం_len = ఆదానం.meta;
  కొలత_t ఆదానం_ఖండాలు = ఆదానం_len / (కొలత_t)136U;
  కొలత_t ఆదానం_rem = ఆదానం_len % (కొలత_t)136U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < ఆదానం_ఖండాలు; i++)
  {
    కొలత_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
    libcrux_sha3_generic_keccak_absorb_ఖండం_80_e90(&s, &lvalue, i0 * (కొలత_t)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd0(&s, &lvalue, ఆదానం_len - ఆదానం_rem, ఆదానం_rem);
  కొలత_t output_len = output.meta;
  కొలత_t output_ఖండాలు = output_len / (కొలత_t)136U;
  కొలత_t output_rem = output_len % (కొలత_t)136U;
  ఒకవేళ (output_ఖండాలు == (కొలత_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (కొలత_t)0U, output_len);
  }
  లేకపోతే
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (కొలత_t)0U, (కొలత_t)136U);
    కొరకు (కొలత_t i = (కొలత_t)1U; i < output_ఖండాలు; i++)
    {
      కొలత_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, i0 * (కొలత_t)136U, (కొలత_t)136U);
    }
    ఒకవేళ (output_rem != (కొలత_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE256 implementation.
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_shake256(
  Eurydice_mut_borrow_ముక్క_u8 digest,
  Eurydice_borrow_ముక్క_u8 దత్తాంశం
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_22(దత్తాంశం, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_block_b4
with const generics
- RATE= 136
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_portable_squeeze_మొదటి_ఖండం_b4_b2(
  స్థిరరాశి Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_sha3_simd_portable_squeeze_9b_b2(self, బహిర్గతం, (కొలత_t)0U, (కొలత_t)136U);
}

/**
 Squeeze the first SHAKE-256 block
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_incremental_shake256_squeeze_మొదటి_ఖండం(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_మొదటి_ఖండం_b4_b2(&s[0U], బహిర్గతం);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_five_blocks_b4
with const generics
- RATE= 168
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_portable_squeeze_మొదటి_five_ఖండాలు_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_sha3_simd_portable_squeeze_9b_60(self, బహిర్గతం, (కొలత_t)0U, (కొలత_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, బహిర్గతం, (కొలత_t)168U, (కొలత_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, బహిర్గతం, (కొలత_t)2U * (కొలత_t)168U, (కొలత_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, బహిర్గతం, (కొలత_t)3U * (కొలత_t)168U, (కొలత_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, బహిర్గతం, (కొలత_t)4U * (కొలత_t)168U, (కొలత_t)168U);
}

/**
 Squeeze five blocks
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_incremental_shake128_squeeze_మొదటి_five_ఖండాలు(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_మొదటి_five_ఖండాలు_b4_60(s, out0);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 168
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_portable_squeeze_తదుపరి_ఖండం_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, బహిర్గతం, ప్రారంభం, (కొలత_t)168U);
}

/**
 Squeeze another block
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_incremental_shake128_squeeze_తదుపరి_ఖండం(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_తదుపరి_ఖండం_b4_60(s, out0, (కొలత_t)0U);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 136
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_portable_squeeze_తదుపరి_ఖండం_b4_b2(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_b2(self, బహిర్గతం, ప్రారంభం, (కొలత_t)136U);
}

/**
 Squeeze the next SHAKE-256 block
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_incremental_shake256_squeeze_తదుపరి_ఖండం(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_తదుపరి_ఖండం_b4_b2(s, బహిర్గతం, (కొలత_t)0U);
}

/**
 Try to complete the internal partial buffer by consuming the minimum required
 number of bytes from the provided `inputs` so that `self.buf` becomes exactly
 one full block of size `RATE`.

 Behaviour:
 - If `self.buf_len` is 0 (no buffered bytes) or already equal to `RATE`
   (already a full block), or if the combined available bytes in `inputs` are
   not enough to reach `RATE`, the function does nothing and returns 0.
 - If `0 < self.buf_len < RATE` and `inputs[..]` contain at least
   `RATE - self.buf_len` bytes, the function copies exactly
   `consumed = RATE - self.buf_len` bytes from each lane `inputs[i]` into
   `self.buf[i]` starting at the current `self.buf_len` offset, sets
   `self.buf_len = RATE`, and returns `consumed`.

 Returns the `consumed` bytes from `inputs` if there's enough buffered
 content to consume, and `0` otherwise.
 If `consumed > 0` is returned, `self.buf` contains a full block to be
 loaded.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.fill_buffer_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
స్థిర అంతఃవరుస కొలత_t
libcrux_sha3_generic_keccak_xof_fill_బఫరు_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  స్థిరరాశి Eurydice_arr_dc *inputs
)
{
  కొలత_t ఆదానం_len = inputs->దత్తాంశం->meta;
  కొలత_t uu____0;
  ఒకవేళ (self->buf_len != (కొలత_t)0U)
  {
    ఒకవేళ (ఆదానం_len >= (కొలత_t)136U - self->buf_len)
    {
      కొలత_t consumed = (కొలత_t)136U - self->buf_len;
      కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)1U; i++)
      {
        కొలత_t i0 = i;
        Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_from_mut_5f(&self->buf.దత్తాంశం[i0],
            self->buf_len),
          Eurydice_ముక్క_subslice_గమ్యం_shared_72(inputs->దత్తాంశం[i0], consumed),
          uint8_t);
      }
      self->buf_len = (కొలత_t)136U;
      uu____0 = consumed;
    }
    లేకపోతే
    {
      uu____0 = (కొలత_t)0U;
    }
  }
  లేకపోతే
  {
    uu____0 = (కొలత_t)0U;
  }
  తిరిగి uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $136size_t
*/
రకనిర్వచనం స్థిరరాశి Eurydice_arr_0b *libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_సంవృతం_94;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_2a
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_call_mut_2a_81(
  స్థిరరాశి Eurydice_arr_0b **_,
  కొలత_t tupled_వాదనలు
)
{
  కొలత_t i = tupled_వాదనలు;
  తిరిగి
    core_array_T_N_as_ముక్క((కొలత_t)136U,
      &_[0U]->దత్తాంశం[i],
      uint8_t,
      Eurydice_borrow_ముక్క_u8);
}

/**
This function found in impl {core::ops::function::FnOnce<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_once_fa
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_call_once_fa_81(
  స్థిరరాశి Eurydice_arr_0b *_,
  కొలత_t _0
)
{
  తిరిగి libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_call_mut_2a_81(&_, _0);
}

/**
 Note: This function exists to work around a hax bug where `core::array::from_fn`
 is extracted with an incorrect explicit type parameter `#(usize -> t_Slice u8)`
 instead of using the typeclass-based implicit parameter `#v_F` from
 `Core_models.Array.from_fn`.
 See: https://github.com/cryspen/hax/issues/1920
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_dc
libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_81(స్థిరరాశి Eurydice_arr_0b *buf)
{
  Eurydice_arr_dc arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)1U; i++)
  {
    arr_struct.దత్తాంశం[i] = libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_call_mut_2a_81(&buf, i);
  }
  తిరిగి arr_struct;
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_full_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
స్థిర అంతఃవరుస కొలత_t
libcrux_sha3_generic_keccak_xof_absorb_నిండిన_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  స్థిరరాశి Eurydice_arr_dc *inputs
)
{
  కొలత_t consumed = libcrux_sha3_generic_keccak_xof_fill_బఫరు_35_e9(self, inputs);
  ఒకవేళ (self->buf_len == (కొలత_t)136U)
  {
    Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_81(&self->buf);
    libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_b2(&self->inner, &borrowed, (కొలత_t)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    self->buf_len = (కొలత_t)0U;
  }
  కొలత_t ఆదానం_గమ్యం_consume = inputs->దత్తాంశం->meta - consumed;
  కొలత_t అంకె_ఖండాలు = ఆదానం_గమ్యం_consume / (కొలత_t)136U;
  కొలత_t remainder = ఆదానం_గమ్యం_consume % (కొలత_t)136U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < అంకె_ఖండాలు; i++)
  {
    కొలత_t i0 = i;
    కొలత_t ప్రారంభం = i0 * (కొలత_t)136U + consumed;
    libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_b2(&self->inner, inputs, ప్రారంభం);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
  }
  తిరిగి remainder;
}

/**
 Absorb

 This function takes any number of bytes to absorb and buffers if it's not enough.
 The function assumes that all input slices in `inputs` have the same length.

 Only a multiple of `RATE` blocks are absorbed.
 For the remaining bytes [`absorb_final`] needs to be called.

 This works best with relatively small `inputs`.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_xof_absorb_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  స్థిరరాశి Eurydice_arr_dc *inputs
)
{
  కొలత_t remainder = libcrux_sha3_generic_keccak_xof_absorb_నిండిన_35_e9(self, inputs);
  ఒకవేళ (remainder > (కొలత_t)0U)
  {
    కొలత_t ఆదానం_len = inputs->దత్తాంశం->meta;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)1U; i++)
    {
      కొలత_t i0 = i;
      Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d42(&self->buf.దత్తాంశం[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ప్రారంభం = self->buf_len,
              .చివర = self->buf_len + remainder
            }
          )),
        Eurydice_ముక్క_subslice_shared_c8(inputs->దత్తాంశం[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ప్రారంభం = ఆదానం_len - remainder,
              .చివర = ఆదానం_len
            }
          )),
        uint8_t);
    }
    self->buf_len += remainder;
  }
}

/**
 Shake256 absorb
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_portable_incremental_absorb_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ముక్క_u8 ఆదానం
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_xof_absorb_35_e9(self, &lvalue);
}

/**
 Absorb a final block.

 The `inputs` block may be empty. Everything in the `inputs` block beyond
 `RATE` bytes is ignored.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_final_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
- DELIMITER= 31
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_xof_absorb_final_35_bd(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  స్థిరరాశి Eurydice_arr_dc *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_e9(self, inputs);
  Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_81(&self->buf);
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_22(&self->inner, &borrowed, (కొలత_t)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
}

/**
 Shake256 absorb final
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_portable_incremental_absorb_final_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ముక్క_u8 ఆదానం
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_xof_absorb_final_35_bd(self, &lvalue);
}

/**
 An all zero block
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.zero_block_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
స్థిర అంతఃవరుస Eurydice_arr_ff libcrux_sha3_generic_keccak_xof_zero_ఖండం_35_e9(శూన్య)
{
  తిరిగి (KRML_CLITERAL(Eurydice_arr_ff){ .దత్తాంశం = { 0U } });
}

/**
 Generate a new keccak xof state.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.new_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
స్థిర అంతఃవరుస libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_generic_keccak_xof_new_35_e9(శూన్య)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_71();
  Eurydice_arr_ff repeat_వ్యక్తీకరణ[1U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)1U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_sha3_generic_keccak_xof_zero_ఖండం_35_e9();
  }
  జ్ఞాపకం_నకలు(lit.buf.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)1U * పరిమాణం (Eurydice_arr_ff));
  lit.buf_len = (కొలత_t)0U;
  lit.sponge = false;
  తిరిగి lit;
}

/**
 Shake256 new state
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
స్థిర అంతఃవరుస libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_portable_incremental_new_42(శూన్య)
{
  తిరిగి libcrux_sha3_generic_keccak_xof_new_35_e9();
}

/**
 Squeeze `N` x `LEN` bytes. Only `N = 1` for now.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, 1usize, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.squeeze_85
with types uint64_t
with const generics
- RATE= 136
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_xof_squeeze_85_76(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  కొలత_t బహిర్గతం_len = బహిర్గతం.meta;
  ఒకవేళ (!(బహిర్గతం_len == (కొలత_t)0U))
  {
    ఒకవేళ (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    }
    ఒకవేళ (బహిర్గతం_len > (కొలత_t)0U)
    {
      కొలత_t ఖండాలు = బహిర్గతం_len / (కొలత_t)136U;
      కొలత_t చివరి = బహిర్గతం_len - బహిర్గతం_len % (కొలత_t)136U;
      ఒకవేళ (ఖండాలు == (కొలత_t)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, బహిర్గతం, (కొలత_t)0U, బహిర్గతం_len);
      }
      లేకపోతే
      {
        libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, బహిర్గతం, (కొలత_t)0U, (కొలత_t)136U);
        కొరకు (కొలత_t i = (కొలత_t)1U; i < ఖండాలు; i++)
        {
          కొలత_t i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner,
            బహిర్గతం,
            i0 * (కొలత_t)136U,
            (కొలత_t)136U);
        }
        ఒకవేళ (చివరి < బహిర్గతం_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, బహిర్గతం, చివరి, బహిర్గతం_len - చివరి);
        }
      }
    }
    self->sponge = true;
  }
}

/**
 Shake256 squeeze
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_portable_incremental_squeeze_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_76(self, బహిర్గతం);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 72
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_c6(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం
)
{
  Eurydice_arr_7c state_flat = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)72U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    కొలత_t స్థానభ్రంశం = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_array_u8x8 arr;
    జ్ఞాపకం_నకలు(arr.దత్తాంశం,
      Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = స్థానభ్రంశం, .చివర = స్థానభ్రంశం + (కొలత_t)8U })).ptr,
      (కొలత_t)8U * పరిమాణం (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ఫలితం_unwrap_26_e0((
          KRML_CLITERAL(core_ఫలితం_ఫలితం_8e){ .ట్యాగ్ = core_ఫలితం_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.దత్తాంశం[i0] = core_అంకె_u64_from_le_బైట్లు(uu____0);
  }
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)72U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    libcrux_sha3_traits_సమితి_ij_71(state,
      i0 / (కొలత_t)5U,
      i0 % (కొలత_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (కొలత_t)5U, i0 % (కొలత_t)5U)[0U] ^
        state_flat.దత్తాంశం[i0]);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 72
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_c6(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_c6(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 72
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_ఖండం_80_e91(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_c6(self, ఆదానం, ప్రారంభం);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 72
- DELIMITER= 6
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_dc(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  Eurydice_arr_ab బఫరు = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d43(&బఫరు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = len })),
    Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = ప్రారంభం, .చివర = ప్రారంభం + len })),
    uint8_t);
  బఫరు.దత్తాంశం[len] = 6U;
  కొలత_t uu____0 = (కొలత_t)72U - (కొలత_t)1U;
  బఫరు.దత్తాంశం[uu____0] = (uint32_t)బఫరు.దత్తాంశం[uu____0] | 128U;
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_c6(state,
    Eurydice_array_గమ్యం_ముక్క_shared_e2(&బఫరు),
    (కొలత_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 72
- DELIMITER= 6
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_dc(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_dc(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 72
- DELIM= 6
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_final_80_bd1(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_dc(self, ఆదానం, ప్రారంభం, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 72
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_store_ఖండం_c6(
  స్థిరరాశి Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  కొలత_t octets = len / (కొలత_t)8U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < octets; i++)
  {
    కొలత_t i0 = i;
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          i0 / (కొలత_t)5U,
          i0 % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + (కొలత_t)8U })),
      Eurydice_array_గమ్యం_ముక్క_shared_6e(&బైట్లు),
      uint8_t);
  }
  కొలత_t మిగిలిన = len % (కొలత_t)8U;
  ఒకవేళ (మిగిలిన > (కొలత_t)0U)
  {
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          octets / (కొలత_t)5U,
          octets % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + len - మిగిలిన;
    Eurydice_mut_borrow_ముక్క_u8
    uu____0 =
      Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + మిగిలిన }));
    Eurydice_ముక్క_copy(uu____0,
      Eurydice_array_గమ్యం_subslice_గమ్యం_shared_21(&బైట్లు, మిగిలిన),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 72
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_squeeze_9b_c6(
  స్థిరరాశి Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_store_ఖండం_c6(self, బహిర్గతం, ప్రారంభం, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 72
- DELIM= 6
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_generic_keccak_portable_keccak1_dc(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_mut_borrow_ముక్క_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  కొలత_t ఆదానం_len = ఆదానం.meta;
  కొలత_t ఆదానం_ఖండాలు = ఆదానం_len / (కొలత_t)72U;
  కొలత_t ఆదానం_rem = ఆదానం_len % (కొలత_t)72U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < ఆదానం_ఖండాలు; i++)
  {
    కొలత_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
    libcrux_sha3_generic_keccak_absorb_ఖండం_80_e91(&s, &lvalue, i0 * (కొలత_t)72U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd1(&s, &lvalue, ఆదానం_len - ఆదానం_rem, ఆదానం_rem);
  కొలత_t output_len = output.meta;
  కొలత_t output_ఖండాలు = output_len / (కొలత_t)72U;
  కొలత_t output_rem = output_len % (కొలత_t)72U;
  ఒకవేళ (output_ఖండాలు == (కొలత_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, (కొలత_t)0U, output_len);
  }
  లేకపోతే
  {
    libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, (కొలత_t)0U, (కొలత_t)72U);
    కొరకు (కొలత_t i = (కొలత_t)1U; i < output_ఖండాలు; i++)
    {
      కొలత_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, i0 * (కొలత_t)72U, (కొలత_t)72U);
    }
    ఒకవేళ (output_rem != (కొలత_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 512 implementation.
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_sha512(
  Eurydice_mut_borrow_ముక్క_u8 digest,
  Eurydice_borrow_ముక్క_u8 దత్తాంశం
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_dc(దత్తాంశం, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 6
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_220(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  Eurydice_arr_ff బఫరు = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d42(&బఫరు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = len })),
    Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = ప్రారంభం, .చివర = ప్రారంభం + len })),
    uint8_t);
  బఫరు.దత్తాంశం[len] = 6U;
  కొలత_t uu____0 = (కొలత_t)136U - (కొలత_t)1U;
  బఫరు.దత్తాంశం[uu____0] = (uint32_t)బఫరు.దత్తాంశం[uu____0] | 128U;
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_b2(state,
    Eurydice_array_గమ్యం_ముక్క_shared_58(&బఫరు),
    (కొలత_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 136
- DELIMITER= 6
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_220(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_220(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 136
- DELIM= 6
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_final_80_bd2(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_220(self, ఆదానం, ప్రారంభం, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 6
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_generic_keccak_portable_keccak1_220(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_mut_borrow_ముక్క_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  కొలత_t ఆదానం_len = ఆదానం.meta;
  కొలత_t ఆదానం_ఖండాలు = ఆదానం_len / (కొలత_t)136U;
  కొలత_t ఆదానం_rem = ఆదానం_len % (కొలత_t)136U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < ఆదానం_ఖండాలు; i++)
  {
    కొలత_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
    libcrux_sha3_generic_keccak_absorb_ఖండం_80_e90(&s, &lvalue, i0 * (కొలత_t)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd2(&s, &lvalue, ఆదానం_len - ఆదానం_rem, ఆదానం_rem);
  కొలత_t output_len = output.meta;
  కొలత_t output_ఖండాలు = output_len / (కొలత_t)136U;
  కొలత_t output_rem = output_len % (కొలత_t)136U;
  ఒకవేళ (output_ఖండాలు == (కొలత_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (కొలత_t)0U, output_len);
  }
  లేకపోతే
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (కొలత_t)0U, (కొలత_t)136U);
    కొరకు (కొలత_t i = (కొలత_t)1U; i < output_ఖండాలు; i++)
    {
      కొలత_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, i0 * (కొలత_t)136U, (కొలత_t)136U);
    }
    ఒకవేళ (output_rem != (కొలత_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 256 implementation.
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_sha256(
  Eurydice_mut_borrow_ముక్క_u8 digest,
  Eurydice_borrow_ముక్క_u8 దత్తాంశం
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_220(దత్తాంశం, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_three_blocks_b4
with const generics
- RATE= 168
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_portable_squeeze_మొదటి_three_ఖండాలు_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_sha3_simd_portable_squeeze_9b_60(self, బహిర్గతం, (కొలత_t)0U, (కొలత_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, బహిర్గతం, (కొలత_t)168U, (కొలత_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, బహిర్గతం, (కొలత_t)2U * (కొలత_t)168U, (కొలత_t)168U);
}

/**
 Squeeze three blocks
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_incremental_shake128_squeeze_మొదటి_three_ఖండాలు(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_మొదటి_three_ఖండాలు_b4_60(s, out0);
}

#నిర్వచించు libcrux_sha3_Algorithm_Sha224 1
#నిర్వచించు libcrux_sha3_Algorithm_Sha256 2
#నిర్వచించు libcrux_sha3_Algorithm_Sha384 3
#నిర్వచించు libcrux_sha3_Algorithm_Sha512 4

రకనిర్వచనం uint8_t libcrux_sha3_Algorithm;

#నిర్వచించు LIBCRUX_SHA3_SHA3_224_DIGEST_కొలత ((కొలత_t)28U)

#నిర్వచించు LIBCRUX_SHA3_SHA3_256_DIGEST_కొలత ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_SHA3_SHA3_384_DIGEST_కొలత ((కొలత_t)48U)

#నిర్వచించు LIBCRUX_SHA3_SHA3_512_DIGEST_కొలత ((కొలత_t)64U)

/**
 Returns the output size of a digest.
*/
స్థిర అంతఃవరుస కొలత_t libcrux_sha3_digest_కొలత(libcrux_sha3_Algorithm బహుళకం)
{
  ఎంపిక (బహుళకం)
  {
    స్థితి libcrux_sha3_Algorithm_Sha224:
      {
        ఆపు;
      }
    స్థితి libcrux_sha3_Algorithm_Sha256:
      {
        తిరిగి LIBCRUX_SHA3_SHA3_256_DIGEST_కొలత;
      }
    స్థితి libcrux_sha3_Algorithm_Sha384:
      {
        తిరిగి LIBCRUX_SHA3_SHA3_384_DIGEST_కొలత;
      }
    స్థితి libcrux_sha3_Algorithm_Sha512:
      {
        తిరిగి LIBCRUX_SHA3_SHA3_512_DIGEST_కొలత;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  తిరిగి LIBCRUX_SHA3_SHA3_224_DIGEST_కొలత;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 144
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_9e(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం
)
{
  Eurydice_arr_7c state_flat = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)144U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    కొలత_t స్థానభ్రంశం = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_array_u8x8 arr;
    జ్ఞాపకం_నకలు(arr.దత్తాంశం,
      Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = స్థానభ్రంశం, .చివర = స్థానభ్రంశం + (కొలత_t)8U })).ptr,
      (కొలత_t)8U * పరిమాణం (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ఫలితం_unwrap_26_e0((
          KRML_CLITERAL(core_ఫలితం_ఫలితం_8e){ .ట్యాగ్ = core_ఫలితం_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.దత్తాంశం[i0] = core_అంకె_u64_from_le_బైట్లు(uu____0);
  }
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)144U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    libcrux_sha3_traits_సమితి_ij_71(state,
      i0 / (కొలత_t)5U,
      i0 % (కొలత_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (కొలత_t)5U, i0 % (కొలత_t)5U)[0U] ^
        state_flat.దత్తాంశం[i0]);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 144
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_9e(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_9e(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 144
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_ఖండం_80_e92(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_9e(self, ఆదానం, ప్రారంభం);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 144
- DELIMITER= 6
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_3a(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  Eurydice_arr_f4 బఫరు = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d44(&బఫరు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = len })),
    Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = ప్రారంభం, .చివర = ప్రారంభం + len })),
    uint8_t);
  బఫరు.దత్తాంశం[len] = 6U;
  కొలత_t uu____0 = (కొలత_t)144U - (కొలత_t)1U;
  బఫరు.దత్తాంశం[uu____0] = (uint32_t)బఫరు.దత్తాంశం[uu____0] | 128U;
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_9e(state,
    Eurydice_array_గమ్యం_ముక్క_shared_38(&బఫరు),
    (కొలత_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 144
- DELIMITER= 6
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_3a(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_3a(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 144
- DELIM= 6
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_final_80_bd3(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_3a(self, ఆదానం, ప్రారంభం, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 144
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_store_ఖండం_9e(
  స్థిరరాశి Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  కొలత_t octets = len / (కొలత_t)8U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < octets; i++)
  {
    కొలత_t i0 = i;
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          i0 / (కొలత_t)5U,
          i0 % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + (కొలత_t)8U })),
      Eurydice_array_గమ్యం_ముక్క_shared_6e(&బైట్లు),
      uint8_t);
  }
  కొలత_t మిగిలిన = len % (కొలత_t)8U;
  ఒకవేళ (మిగిలిన > (కొలత_t)0U)
  {
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          octets / (కొలత_t)5U,
          octets % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + len - మిగిలిన;
    Eurydice_mut_borrow_ముక్క_u8
    uu____0 =
      Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + మిగిలిన }));
    Eurydice_ముక్క_copy(uu____0,
      Eurydice_array_గమ్యం_subslice_గమ్యం_shared_21(&బైట్లు, మిగిలిన),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 144
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_squeeze_9b_9e(
  స్థిరరాశి Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_store_ఖండం_9e(self, బహిర్గతం, ప్రారంభం, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 144
- DELIM= 6
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_generic_keccak_portable_keccak1_3a(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_mut_borrow_ముక్క_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  కొలత_t ఆదానం_len = ఆదానం.meta;
  కొలత_t ఆదానం_ఖండాలు = ఆదానం_len / (కొలత_t)144U;
  కొలత_t ఆదానం_rem = ఆదానం_len % (కొలత_t)144U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < ఆదానం_ఖండాలు; i++)
  {
    కొలత_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
    libcrux_sha3_generic_keccak_absorb_ఖండం_80_e92(&s, &lvalue, i0 * (కొలత_t)144U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd3(&s, &lvalue, ఆదానం_len - ఆదానం_rem, ఆదానం_rem);
  కొలత_t output_len = output.meta;
  కొలత_t output_ఖండాలు = output_len / (కొలత_t)144U;
  కొలత_t output_rem = output_len % (కొలత_t)144U;
  ఒకవేళ (output_ఖండాలు == (కొలత_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, (కొలత_t)0U, output_len);
  }
  లేకపోతే
  {
    libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, (కొలత_t)0U, (కొలత_t)144U);
    కొరకు (కొలత_t i = (కొలత_t)1U; i < output_ఖండాలు; i++)
    {
      కొలత_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, i0 * (కొలత_t)144U, (కొలత_t)144U);
    }
    ఒకవేళ (output_rem != (కొలత_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 224 implementation.
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_sha224(
  Eurydice_mut_borrow_ముక్క_u8 digest,
  Eurydice_borrow_ముక్క_u8 దత్తాంశం
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_3a(దత్తాంశం, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 104
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_53(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం
)
{
  Eurydice_arr_7c state_flat = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)104U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    కొలత_t స్థానభ్రంశం = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_array_u8x8 arr;
    జ్ఞాపకం_నకలు(arr.దత్తాంశం,
      Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = స్థానభ్రంశం, .చివర = స్థానభ్రంశం + (కొలత_t)8U })).ptr,
      (కొలత_t)8U * పరిమాణం (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ఫలితం_unwrap_26_e0((
          KRML_CLITERAL(core_ఫలితం_ఫలితం_8e){ .ట్యాగ్ = core_ఫలితం_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.దత్తాంశం[i0] = core_అంకె_u64_from_le_బైట్లు(uu____0);
  }
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)104U / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    libcrux_sha3_traits_సమితి_ij_71(state,
      i0 / (కొలత_t)5U,
      i0 % (కొలత_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (కొలత_t)5U, i0 % (కొలత_t)5U)[0U] ^
        state_flat.దత్తాంశం[i0]);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 104
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_53(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_53(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 104
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_ఖండం_80_e93(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_53(self, ఆదానం, ప్రారంభం);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 104
- DELIMITER= 6
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_dc0(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ముక్క_u8 ఖండాలు,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  Eurydice_arr_c4 బఫరు = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d45(&బఫరు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = len })),
    Eurydice_ముక్క_subslice_shared_c8(ఖండాలు,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = ప్రారంభం, .చివర = ప్రారంభం + len })),
    uint8_t);
  బఫరు.దత్తాంశం[len] = 6U;
  కొలత_t uu____0 = (కొలత_t)104U - (కొలత_t)1U;
  బఫరు.దత్తాంశం[uu____0] = (uint32_t)బఫరు.దత్తాంశం[uu____0] | 128U;
  libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_53(state,
    Eurydice_array_గమ్యం_ముక్క_shared_72(&బఫరు),
    (కొలత_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 104
- DELIMITER= 6
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_dc0(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_dc0(self, ఆదానం->దత్తాంశం[0U], ప్రారంభం, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 104
- DELIM= 6
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_absorb_final_80_bd4(
  Eurydice_arr_7c *self,
  స్థిరరాశి Eurydice_arr_dc *ఆదానం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_dc0(self, ఆదానం, ప్రారంభం, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 104
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_simd_portable_store_ఖండం_53(
  స్థిరరాశి Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  కొలత_t octets = len / (కొలత_t)8U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < octets; i++)
  {
    కొలత_t i0 = i;
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          i0 / (కొలత_t)5U,
          i0 % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + (కొలత_t)8U * i0;
    Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + (కొలత_t)8U })),
      Eurydice_array_గమ్యం_ముక్క_shared_6e(&బైట్లు),
      uint8_t);
  }
  కొలత_t మిగిలిన = len % (కొలత_t)8U;
  ఒకవేళ (మిగిలిన > (కొలత_t)0U)
  {
    Eurydice_array_u8x8
    బైట్లు =
      core_అంకె_u64_గమ్యం_le_బైట్లు(libcrux_sha3_traits_get_ij_71(s,
          octets / (కొలత_t)5U,
          octets % (కొలత_t)5U)[0U]);
    కొలత_t బహిర్గతం_pos = ప్రారంభం + len - మిగిలిన;
    Eurydice_mut_borrow_ముక్క_u8
    uu____0 =
      Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = బహిర్గతం_pos, .చివర = బహిర్గతం_pos + మిగిలిన }));
    Eurydice_ముక్క_copy(uu____0,
      Eurydice_array_గమ్యం_subslice_గమ్యం_shared_21(&బైట్లు, మిగిలిన),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 104
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_simd_portable_squeeze_9b_53(
  స్థిరరాశి Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం,
  కొలత_t ప్రారంభం,
  కొలత_t len
)
{
  libcrux_sha3_simd_portable_store_ఖండం_53(self, బహిర్గతం, ప్రారంభం, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 104
- DELIM= 6
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_generic_keccak_portable_keccak1_dc0(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_mut_borrow_ముక్క_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  కొలత_t ఆదానం_len = ఆదానం.meta;
  కొలత_t ఆదానం_ఖండాలు = ఆదానం_len / (కొలత_t)104U;
  కొలత_t ఆదానం_rem = ఆదానం_len % (కొలత_t)104U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < ఆదానం_ఖండాలు; i++)
  {
    కొలత_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
    libcrux_sha3_generic_keccak_absorb_ఖండం_80_e93(&s, &lvalue, i0 * (కొలత_t)104U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd4(&s, &lvalue, ఆదానం_len - ఆదానం_rem, ఆదానం_rem);
  కొలత_t output_len = output.meta;
  కొలత_t output_ఖండాలు = output_len / (కొలత_t)104U;
  కొలత_t output_rem = output_len % (కొలత_t)104U;
  ఒకవేళ (output_ఖండాలు == (కొలత_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, (కొలత_t)0U, output_len);
  }
  లేకపోతే
  {
    libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, (కొలత_t)0U, (కొలత_t)104U);
    కొరకు (కొలత_t i = (కొలత_t)1U; i < output_ఖండాలు; i++)
    {
      కొలత_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, i0 * (కొలత_t)104U, (కొలత_t)104U);
    }
    ఒకవేళ (output_rem != (కొలత_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 384 implementation.
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_portable_sha384(
  Eurydice_mut_borrow_ముక్క_u8 digest,
  Eurydice_borrow_ముక్క_u8 దత్తాంశం
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_dc0(దత్తాంశం, digest);
}

/**
 SHA3 224

 Preconditions:
 - `digest.len() == 28`
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_sha224_ema(Eurydice_mut_borrow_ముక్క_u8 digest, Eurydice_borrow_ముక్క_u8 payload)
{
  libcrux_sha3_portable_sha224(digest, payload);
}

/**
 SHA3 224
*/
స్థిర అంతఃవరుస Eurydice_arr_a2 libcrux_sha3_sha224(Eurydice_borrow_ముక్క_u8 దత్తాంశం)
{
  Eurydice_arr_a2 బహిర్గతం = { .దత్తాంశం = { 0U } };
  libcrux_sha3_sha224_ema(Eurydice_array_గమ్యం_ముక్క_mut_5e(&బహిర్గతం), దత్తాంశం);
  తిరిగి బహిర్గతం;
}

/**
 SHA3 256
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_sha256_ema(Eurydice_mut_borrow_ముక్క_u8 digest, Eurydice_borrow_ముక్క_u8 payload)
{
  libcrux_sha3_portable_sha256(digest, payload);
}

/**
 SHA3 256
*/
స్థిర అంతఃవరుస Eurydice_arr_ec libcrux_sha3_sha256(Eurydice_borrow_ముక్క_u8 దత్తాంశం)
{
  Eurydice_arr_ec బహిర్గతం = { .దత్తాంశం = { 0U } };
  libcrux_sha3_sha256_ema(Eurydice_array_గమ్యం_ముక్క_mut_01(&బహిర్గతం), దత్తాంశం);
  తిరిగి బహిర్గతం;
}

/**
 SHA3 384
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_sha384_ema(Eurydice_mut_borrow_ముక్క_u8 digest, Eurydice_borrow_ముక్క_u8 payload)
{
  libcrux_sha3_portable_sha384(digest, payload);
}

/**
 SHA3 384
*/
స్థిర అంతఃవరుస Eurydice_arr_65 libcrux_sha3_sha384(Eurydice_borrow_ముక్క_u8 దత్తాంశం)
{
  Eurydice_arr_65 బహిర్గతం = { .దత్తాంశం = { 0U } };
  libcrux_sha3_sha384_ema(Eurydice_array_గమ్యం_ముక్క_mut_9f(&బహిర్గతం), దత్తాంశం);
  తిరిగి బహిర్గతం;
}

/**
 SHA3 512
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_sha512_ema(Eurydice_mut_borrow_ముక్క_u8 digest, Eurydice_borrow_ముక్క_u8 payload)
{
  libcrux_sha3_portable_sha512(digest, payload);
}

/**
 SHA3 512
*/
స్థిర అంతఃవరుస Eurydice_arr_c7 libcrux_sha3_sha512(Eurydice_borrow_ముక్క_u8 దత్తాంశం)
{
  Eurydice_arr_c7 బహిర్గతం = { .దత్తాంశం = { 0U } };
  libcrux_sha3_sha512_ema(Eurydice_array_గమ్యం_ముక్క_mut_17(&బహిర్గతం), దత్తాంశం);
  తిరిగి బహిర్గతం;
}

/**
 SHAKE 128

 Writes `out.len()` bytes.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_shake128_ema(Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం, Eurydice_borrow_ముక్క_u8 దత్తాంశం)
{
  libcrux_sha3_portable_shake128(బహిర్గతం, దత్తాంశం);
}

/**
 SHAKE 256

 Writes `out.len()` bytes.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_shake256_ema(Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం, Eurydice_borrow_ముక్క_u8 దత్తాంశం)
{
  libcrux_sha3_portable_shake256(బహిర్గతం, దత్తాంశం);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $168size_t
*/
రకనిర్వచనం నిర్మాణం libcrux_sha3_generic_keccak_xof_KeccakXofState_55_s
{
  Eurydice_arr_7c inner;
  Eurydice_arr_88 buf;
  కొలత_t buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_55;

రకనిర్వచనం libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_portable_incremental_Shake128Xof;

/**
 Try to complete the internal partial buffer by consuming the minimum required
 number of bytes from the provided `inputs` so that `self.buf` becomes exactly
 one full block of size `RATE`.

 Behaviour:
 - If `self.buf_len` is 0 (no buffered bytes) or already equal to `RATE`
   (already a full block), or if the combined available bytes in `inputs` are
   not enough to reach `RATE`, the function does nothing and returns 0.
 - If `0 < self.buf_len < RATE` and `inputs[..]` contain at least
   `RATE - self.buf_len` bytes, the function copies exactly
   `consumed = RATE - self.buf_len` bytes from each lane `inputs[i]` into
   `self.buf[i]` starting at the current `self.buf_len` offset, sets
   `self.buf_len = RATE`, and returns `consumed`.

 Returns the `consumed` bytes from `inputs` if there's enough buffered
 content to consume, and `0` otherwise.
 If `consumed > 0` is returned, `self.buf` contains a full block to be
 loaded.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.fill_buffer_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
స్థిర అంతఃవరుస కొలత_t
libcrux_sha3_generic_keccak_xof_fill_బఫరు_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  స్థిరరాశి Eurydice_arr_dc *inputs
)
{
  కొలత_t ఆదానం_len = inputs->దత్తాంశం->meta;
  కొలత_t uu____0;
  ఒకవేళ (self->buf_len != (కొలత_t)0U)
  {
    ఒకవేళ (ఆదానం_len >= (కొలత_t)168U - self->buf_len)
    {
      కొలత_t consumed = (కొలత_t)168U - self->buf_len;
      కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)1U; i++)
      {
        కొలత_t i0 = i;
        Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_from_mut_5f0(&self->buf.దత్తాంశం[i0],
            self->buf_len),
          Eurydice_ముక్క_subslice_గమ్యం_shared_72(inputs->దత్తాంశం[i0], consumed),
          uint8_t);
      }
      self->buf_len = (కొలత_t)168U;
      uu____0 = consumed;
    }
    లేకపోతే
    {
      uu____0 = (కొలత_t)0U;
    }
  }
  లేకపోతే
  {
    uu____0 = (కొలత_t)0U;
  }
  తిరిగి uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $168size_t
*/
రకనిర్వచనం స్థిరరాశి Eurydice_arr_88 *libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_సంవృతం_48;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_2a
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_call_mut_2a_810(
  స్థిరరాశి Eurydice_arr_88 **_,
  కొలత_t tupled_వాదనలు
)
{
  కొలత_t i = tupled_వాదనలు;
  తిరిగి
    core_array_T_N_as_ముక్క((కొలత_t)168U,
      &_[0U]->దత్తాంశం[i],
      uint8_t,
      Eurydice_borrow_ముక్క_u8);
}

/**
This function found in impl {core::ops::function::FnOnce<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_once_fa
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_call_once_fa_810(
  స్థిరరాశి Eurydice_arr_88 *_,
  కొలత_t _0
)
{
  తిరిగి libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_call_mut_2a_810(&_, _0);
}

/**
 Note: This function exists to work around a hax bug where `core::array::from_fn`
 is extracted with an incorrect explicit type parameter `#(usize -> t_Slice u8)`
 instead of using the typeclass-based implicit parameter `#v_F` from
 `Core_models.Array.from_fn`.
 See: https://github.com/cryspen/hax/issues/1920
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_dc
libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_810(స్థిరరాశి Eurydice_arr_88 *buf)
{
  Eurydice_arr_dc arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)1U; i++)
  {
    arr_struct.దత్తాంశం[i] = libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_call_mut_2a_810(&buf, i);
  }
  తిరిగి arr_struct;
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_full_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
స్థిర అంతఃవరుస కొలత_t
libcrux_sha3_generic_keccak_xof_absorb_నిండిన_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  స్థిరరాశి Eurydice_arr_dc *inputs
)
{
  కొలత_t consumed = libcrux_sha3_generic_keccak_xof_fill_బఫరు_35_e90(self, inputs);
  ఒకవేళ (self->buf_len == (కొలత_t)168U)
  {
    Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_810(&self->buf);
    libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_60(&self->inner, &borrowed, (కొలత_t)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    self->buf_len = (కొలత_t)0U;
  }
  కొలత_t ఆదానం_గమ్యం_consume = inputs->దత్తాంశం->meta - consumed;
  కొలత_t అంకె_ఖండాలు = ఆదానం_గమ్యం_consume / (కొలత_t)168U;
  కొలత_t remainder = ఆదానం_గమ్యం_consume % (కొలత_t)168U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < అంకె_ఖండాలు; i++)
  {
    కొలత_t i0 = i;
    కొలత_t ప్రారంభం = i0 * (కొలత_t)168U + consumed;
    libcrux_sha3_simd_portable_ఎక్కించు_ఖండం_a1_60(&self->inner, inputs, ప్రారంభం);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
  }
  తిరిగి remainder;
}

/**
 Absorb

 This function takes any number of bytes to absorb and buffers if it's not enough.
 The function assumes that all input slices in `inputs` have the same length.

 Only a multiple of `RATE` blocks are absorbed.
 For the remaining bytes [`absorb_final`] needs to be called.

 This works best with relatively small `inputs`.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_xof_absorb_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  స్థిరరాశి Eurydice_arr_dc *inputs
)
{
  కొలత_t remainder = libcrux_sha3_generic_keccak_xof_absorb_నిండిన_35_e90(self, inputs);
  ఒకవేళ (remainder > (కొలత_t)0U)
  {
    కొలత_t ఆదానం_len = inputs->దత్తాంశం->meta;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)1U; i++)
    {
      కొలత_t i0 = i;
      Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d41(&self->buf.దత్తాంశం[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ప్రారంభం = self->buf_len,
              .చివర = self->buf_len + remainder
            }
          )),
        Eurydice_ముక్క_subslice_shared_c8(inputs->దత్తాంశం[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ప్రారంభం = ఆదానం_len - remainder,
              .చివర = ఆదానం_len
            }
          )),
        uint8_t);
    }
    self->buf_len += remainder;
  }
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_portable_incremental_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_borrow_ముక్క_u8 ఆదానం
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_xof_absorb_35_e90(self, &lvalue);
}

/**
 Absorb a final block.

 The `inputs` block may be empty. Everything in the `inputs` block beyond
 `RATE` bytes is ignored.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_final_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
- DELIMITER= 31
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_xof_absorb_final_35_bd0(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  స్థిరరాశి Eurydice_arr_dc *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_e90(self, inputs);
  Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_గమ్యం_slices_810(&self->buf);
  libcrux_sha3_simd_portable_ఎక్కించు_చివరి_a1_37(&self->inner, &borrowed, (కొలత_t)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_portable_incremental_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_borrow_ముక్క_u8 ఆదానం
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .దత్తాంశం = { ఆదానం } };
  libcrux_sha3_generic_keccak_xof_absorb_final_35_bd0(self, &lvalue);
}

/**
 An all zero block
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.zero_block_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
స్థిర అంతఃవరుస Eurydice_arr_c5 libcrux_sha3_generic_keccak_xof_zero_ఖండం_35_e90(శూన్య)
{
  తిరిగి (KRML_CLITERAL(Eurydice_arr_c5){ .దత్తాంశం = { 0U } });
}

/**
 Generate a new keccak xof state.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.new_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
స్థిర అంతఃవరుస libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_generic_keccak_xof_new_35_e90(శూన్య)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_71();
  Eurydice_arr_c5 repeat_వ్యక్తీకరణ[1U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)1U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_sha3_generic_keccak_xof_zero_ఖండం_35_e90();
  }
  జ్ఞాపకం_నకలు(lit.buf.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)1U * పరిమాణం (Eurydice_arr_c5));
  lit.buf_len = (కొలత_t)0U;
  lit.sponge = false;
  తిరిగి lit;
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
స్థిర అంతఃవరుస libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_portable_incremental_new_26(శూన్య)
{
  తిరిగి libcrux_sha3_generic_keccak_xof_new_35_e90();
}

/**
 Squeeze `N` x `LEN` bytes. Only `N = 1` for now.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, 1usize, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.squeeze_85
with types uint64_t
with const generics
- RATE= 168
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_sha3_generic_keccak_xof_squeeze_85_2a(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  కొలత_t బహిర్గతం_len = బహిర్గతం.meta;
  ఒకవేళ (!(బహిర్గతం_len == (కొలత_t)0U))
  {
    ఒకవేళ (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    }
    ఒకవేళ (బహిర్గతం_len > (కొలత_t)0U)
    {
      కొలత_t ఖండాలు = బహిర్గతం_len / (కొలత_t)168U;
      కొలత_t చివరి = బహిర్గతం_len - బహిర్గతం_len % (కొలత_t)168U;
      ఒకవేళ (ఖండాలు == (కొలత_t)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, బహిర్గతం, (కొలత_t)0U, బహిర్గతం_len);
      }
      లేకపోతే
      {
        libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, బహిర్గతం, (కొలత_t)0U, (కొలత_t)168U);
        కొరకు (కొలత_t i = (కొలత_t)1U; i < ఖండాలు; i++)
        {
          కొలత_t i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner,
            బహిర్గతం,
            i0 * (కొలత_t)168U,
            (కొలత_t)168U);
        }
        ఒకవేళ (చివరి < బహిర్గతం_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, బహిర్గతం, చివరి, బహిర్గతం_len - చివరి);
        }
      }
    }
    self->sponge = true;
  }
}

/**
 Shake128 squeeze
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_sha3_portable_incremental_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_2a(self, బహిర్గతం);
}

/**
This function found in impl {core::clone::Clone for libcrux_sha3::portable::KeccakState}
*/
స్థిర అంతఃవరుస Eurydice_arr_7c libcrux_sha3_portable_clone_fe(స్థిరరాశి Eurydice_arr_7c *self)
{
  తిరిగి self[0U];
}

/**
This function found in impl {core::clone::Clone for libcrux_sha3::Algorithm}
*/
స్థిర అంతఃవరుస libcrux_sha3_Algorithm libcrux_sha3_clone_e6(స్థిరరాశి libcrux_sha3_Algorithm *self)
{
  తిరిగి self[0U];
}

/**
This function found in impl {core::convert::From<libcrux_sha3::Algorithm> for u32}
*/
స్థిర అంతఃవరుస uint32_t libcrux_sha3_from_6c(libcrux_sha3_Algorithm v)
{
  ఎంపిక (v)
  {
    స్థితి libcrux_sha3_Algorithm_Sha224:
      {
        ఆపు;
      }
    స్థితి libcrux_sha3_Algorithm_Sha256:
      {
        తిరిగి 2U;
      }
    స్థితి libcrux_sha3_Algorithm_Sha384:
      {
        తిరిగి 3U;
      }
    స్థితి libcrux_sha3_Algorithm_Sha512:
      {
        తిరిగి 4U;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  తిరిగి 1U;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_sha3_portable_KeccakState
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_1b0_s { Eurydice_arr_7c దత్తాంశం[3U]; } Eurydice_arr_1b0;

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు libcrux_sha3_portable_H_DEFINED
#అయితే_ముగింపు /* libcrux_sha3_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mlkem_core.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే libcrux_mlkem_core_H
#నిర్వచించు libcrux_mlkem_core_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


#నిర్వచించు LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_KEM_CONSTANTS_బిట్లు_చొప్పున_COEFFICIENT ((కొలత_t)12U)

#నిర్వచించు LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT ((కొలత_t)256U)

#నిర్వచించు LIBCRUX_ML_KEM_CONSTANTS_బిట్లు_చొప్పున_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * (కొలత_t)12U)

#నిర్వచించు LIBCRUX_ML_KEM_CONSTANTS_బైట్లు_చొప్పున_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_బిట్లు_చొప్పున_RING_ELEMENT / (కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_కీలకం_GENERATION_విత్తనం_కొలత ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_KEM_CONSTANTS_G_DIGEST_కొలత ((కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_కొలత ((కొలత_t)32U)

/**
 K * BITS_PER_RING_ELEMENT / 8

 [eurydice] Note that we can't use const generics here because that breaks
            C extraction with eurydice.
*/
స్థిర అంతఃవరుస కొలత_t libcrux_ml_kem_constants_ranked_బైట్లు_చొప్పున_ring_element(కొలత_t rank)
{
  తిరిగి rank * LIBCRUX_ML_KEM_CONSTANTS_బిట్లు_చొప్పున_RING_ELEMENT / (కొలత_t)8U;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
స్థిర KRML_MUSTINLINE uint8_t libcrux_secrets_int_as_u8_f5(int16_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_90((uint8_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u8}
*/
స్థిర KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_59(uint8_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_39((int16_t)(uint32_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_90(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
స్థిర KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_f5(int16_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_a8((int32_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i32}
*/
స్థిర KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_36(int32_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_39((int16_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_a8(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
స్థిర KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_b8(uint32_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_a8((int32_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
స్థిర KRML_MUSTINLINE uint16_t libcrux_secrets_int_as_u16_f5(int16_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_de((uint16_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
స్థిర KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_ca(uint16_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_39((int16_t)(uint32_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
స్థిర KRML_MUSTINLINE uint64_t libcrux_secrets_int_as_u64_ca(uint16_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_49((uint64_t)(uint32_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u64}
*/
స్థిర KRML_MUSTINLINE uint32_t libcrux_secrets_int_as_u32_a3(uint64_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_df((uint32_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_49(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
స్థిర KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_b8(uint32_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_39((int16_t)libcrux_secrets_int_ప్రజా_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
స్థిర KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_f5(int16_t self)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(libcrux_secrets_int_ప్రజా_integers_declassify_d8_39(self));
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 32
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_utils_into_padded_array_ce(Eurydice_borrow_ముక్క_u8 ముక్క)
{
  Eurydice_arr_ec బహిర్గతం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d46(&బహిర్గతం,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = ముక్క.meta })),
    ముక్క,
    uint8_t);
  తిరిగి బహిర్గతం;
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.default_d3
with const generics
- SIZE= 2400
*/
స్థిర అంతఃవరుస Eurydice_arr_7d libcrux_ml_kem_types_default_d3_79(శూన్య)
{
  తిరిగి (KRML_CLITERAL(Eurydice_arr_7d){ .దత్తాంశం = { 0U } });
}

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemPublicKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_51
with const generics
- SIZE= 1184
*/
స్థిర అంతఃవరుస Eurydice_arr_5f libcrux_ml_kem_types_from_51_3d(Eurydice_arr_5f విలువ)
{
  తిరిగి విలువ;
}

రకనిర్వచనం నిర్మాణం libcrux_ml_kem_mlkem768_Ml_Kem768_కీలకం_Pair_s
{
  Eurydice_arr_7d sk;
  Eurydice_arr_5f pk;
}
libcrux_ml_kem_mlkem768_Ml_Kem768_కీలకం_Pair;

/**
 Create a new [`MlKemKeyPair`] from the secret and public key.
*/
/**
This function found in impl {libcrux_ml_kem::types::MlKemKeyPair<PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_17
with const generics
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర అంతఃవరుస libcrux_ml_kem_mlkem768_Ml_Kem768_కీలకం_Pair
libcrux_ml_kem_types_from_17_bc(Eurydice_arr_7d sk, Eurydice_arr_5f pk)
{
  తిరిగి (KRML_CLITERAL(libcrux_ml_kem_mlkem768_Ml_Kem768_కీలకం_Pair){ .sk = sk, .pk = pk });
}

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_b2
with const generics
- SIZE= 2400
*/
స్థిర అంతఃవరుస Eurydice_arr_7d libcrux_ml_kem_types_from_b2_79(Eurydice_arr_7d విలువ)
{
  తిరిగి విలువ;
}

/**
A monomorphic instance of n-tuple
with types libcrux_ml_kem_mlkem768_MlKem768Ciphertext, Eurydice_arr_ec

*/
రకనిర్వచనం నిర్మాణం tuple_f4_s
{
  Eurydice_arr_2b fst;
  Eurydice_arr_ec snd;
}
tuple_f4;

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_19
with const generics
- SIZE= 1088
*/
స్థిర అంతఃవరుస Eurydice_arr_2b libcrux_ml_kem_types_from_19_52(Eurydice_arr_2b విలువ)
{
  తిరిగి విలువ;
}

/**
 A reference to the raw byte slice.
*/
/**
This function found in impl {libcrux_ml_kem::types::MlKemPublicKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_slice_e6
with const generics
- SIZE= 1184
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_5f
*libcrux_ml_kem_types_as_ముక్క_e6_3d(స్థిరరాశి Eurydice_arr_5f *self)
{
  తిరిగి self;
}

/**
 A reference to the raw byte slice.
*/
/**
This function found in impl {libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_slice_a9
with const generics
- SIZE= 1088
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_2b
*libcrux_ml_kem_types_as_ముక్క_a9_52(స్థిరరాశి Eurydice_arr_2b *self)
{
  తిరిగి self;
}

/**
A monomorphic instance of libcrux_ml_kem.utils.prf_input_inc
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE uint8_t
libcrux_ml_kem_utils_prf_ఆదానం_inc_78(Eurydice_arr_fd *prf_inputs, uint8_t domain_separator)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    prf_inputs->దత్తాంశం[i0].దత్తాంశం[32U] = domain_separator;
    domain_separator = (uint32_t)domain_separator + 1U;
  }
  తిరిగి domain_separator;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 33
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_fa0
libcrux_ml_kem_utils_into_padded_array_29(Eurydice_borrow_ముక్క_u8 ముక్క)
{
  Eurydice_arr_fa0 బహిర్గతం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d412(&బహిర్గతం,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = ముక్క.meta })),
    ముక్క,
    uint8_t);
  తిరిగి బహిర్గతం;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 34
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_31
libcrux_ml_kem_utils_into_padded_array_de(Eurydice_borrow_ముక్క_u8 ముక్క)
{
  Eurydice_arr_31 బహిర్గతం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d40(&బహిర్గతం,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = ముక్క.meta })),
    ముక్క,
    uint8_t);
  తిరిగి బహిర్గతం;
}

/**
This function found in impl {core::convert::AsRef<[u8]> for libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_ref_c1
with const generics
- SIZE= 1088
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
libcrux_ml_kem_types_as_ref_c1_52(స్థిరరాశి Eurydice_arr_2b *self)
{
  తిరిగి Eurydice_array_గమ్యం_ముక్క_shared_06(self);
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 1120
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_af
libcrux_ml_kem_utils_into_padded_array_66(Eurydice_borrow_ముక్క_u8 ముక్క)
{
  Eurydice_arr_af బహిర్గతం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d411(&బహిర్గతం,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = ముక్క.meta })),
    ముక్క,
    uint8_t);
  తిరిగి బహిర్గతం;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 64
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_c7
libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_borrow_ముక్క_u8 ముక్క)
{
  Eurydice_arr_c7 బహిర్గతం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d410(&బహిర్గతం,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = ముక్క.meta })),
    ముక్క,
    uint8_t);
  తిరిగి బహిర్గతం;
}

రకనిర్వచనం నిర్మాణం Eurydice_borrow_ముక్క_u8_x4_s
{
  Eurydice_borrow_ముక్క_u8 fst;
  Eurydice_borrow_ముక్క_u8 snd;
  Eurydice_borrow_ముక్క_u8 thd;
  Eurydice_borrow_ముక్క_u8 f3;
}
Eurydice_borrow_ముక్క_u8_x4;

రకనిర్వచనం నిర్మాణం Eurydice_borrow_ముక్క_u8_x2_s
{
  Eurydice_borrow_ముక్క_u8 fst;
  Eurydice_borrow_ముక్క_u8 snd;
}
Eurydice_borrow_ముక్క_u8_x2;

/**
 Unpack an incoming private key into it's different parts.

 We have this here in types to extract into a common core for C.
*/
/**
A monomorphic instance of libcrux_ml_kem.types.unpack_private_key
with const generics
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8_x4
libcrux_ml_kem_types_unpack_వ్యక్తిగత_కీలకం_64(Eurydice_borrow_ముక్క_u8 వ్యక్తిగత_కీలకం)
{
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(వ్యక్తిగత_కీలకం,
      (కొలత_t)1152U,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 ind_cpa_secret_కీలకం = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 secret_key0 = uu____0.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(secret_key0,
      (కొలత_t)1184U,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 ind_cpa_ప్రజా_కీలకం = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 secret_కీలకం = uu____1.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____2 =
    Eurydice_ముక్క_విభజించు_at(secret_కీలకం,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 ind_cpa_ప్రజా_కీలకం_hash = uu____2.fst;
  Eurydice_borrow_ముక్క_u8 implicit_rejection_విలువ = uu____2.snd;
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_borrow_ముక్క_u8_x4){
        .fst = ind_cpa_secret_కీలకం,
        .snd = ind_cpa_ప్రజా_కీలకం,
        .thd = ind_cpa_ప్రజా_కీలకం_hash,
        .f3 = implicit_rejection_విలువ
      }
    );
}

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు libcrux_mlkem_core_H_DEFINED
#అయితే_ముగింపు /* libcrux_mlkem_core_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa_core.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే libcrux_mldsa_core_H
#నిర్వచించు libcrux_mldsa_core_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


#నిర్వచించు libcrux_ml_dsa_constants_Eta_Two 2
#నిర్వచించు libcrux_ml_dsa_constants_Eta_Four 4

రకనిర్వచనం uint8_t libcrux_ml_dsa_constants_Eta;

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_లోపల_SIMD_UNIT ((కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_లోపల_RING_ELEMENT ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_క్రింది_PART_యొక్క_T ((కొలత_t)13U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_క్షేత్రం_MODULUS_MINUS_ONE_బిట్టు_నిడివి ((కొలత_t)23U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_పై_PART_యొక్క_T (LIBCRUX_ML_DSA_CONSTANTS_క్షేత్రం_MODULUS_MINUS_ONE_బిట్టు_నిడివి - LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_క్రింది_PART_యొక్క_T)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_బైట్లు_FOR_VERIFICATION_కీలకం_HASH ((కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT ((కొలత_t)256U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN ((కొలత_t)255U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_క్షేత్రం_MODULUS (8380417)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V261_888 (261888)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V95_232 (95232)

రకనిర్వచనం int32_t libcrux_ml_dsa_constants_Gamma2;

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_కీలకం_GENERATION_RANDOMNESS_కొలత ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ముసుగు_విత్తనం_కొలత ((కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_సందేశం_REPRESENTATIVE_కొలత ((కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN ((కొలత_t)814U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T0_S_కొలత (LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_క్రింది_PART_యొక్క_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT / (కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T1_S_కొలత (LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_పై_PART_యొక్క_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT / (కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_ERROR_VECTORS_కొలత ((కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_SIGNING_కొలత ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_SIGNING_RANDOMNESS_కొలత ((కొలత_t)32U)

స్థిర అంతఃవరుస int32_t
libcrux_ml_dsa_constants_beta(
  కొలత_t ones_లోపల_verifier_challenge,
  libcrux_ml_dsa_constants_Eta eta
)
{
  కొలత_t eta_val;
  ఎంపిక (eta)
  {
    స్థితి libcrux_ml_dsa_constants_Eta_Two:
      {
        eta_val = (కొలత_t)2U;
        ఆపు;
      }
    స్థితి libcrux_ml_dsa_constants_Eta_Four:
      {
        eta_val = (కొలత_t)4U;
        ఆపు;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  తిరిగి (int32_t)(ones_లోపల_verifier_challenge * eta_val);
}

స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_constants_commitment_ring_element_కొలత(కొలత_t బిట్లు_చొప్పున_commitment_coefficient)
{
  తిరిగి
    బిట్లు_చొప్పున_commitment_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT /
      (కొలత_t)8U;
}

స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_constants_commitment_సదిశ_కొలత(
  కొలత_t బిట్లు_చొప్పున_commitment_coefficient,
  కొలత_t అడ్డువరుసలు_లోపల_a
)
{
  తిరిగి
    libcrux_ml_dsa_constants_commitment_ring_element_కొలత(బిట్లు_చొప్పున_commitment_coefficient) *
      అడ్డువరుసలు_లోపల_a;
}

స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_constants_error_ring_element_కొలత(కొలత_t బిట్లు_చొప్పున_error_coefficient)
{
  తిరిగి
    బిట్లు_చొప్పున_error_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT / (కొలత_t)8U;
}

స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_constants_gamma1_ring_element_కొలత(కొలత_t బిట్లు_చొప్పున_gamma1_coefficient)
{
  తిరిగి
    బిట్లు_చొప్పున_gamma1_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT /
      (కొలత_t)8U;
}

స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_constants_signature_కొలత(
  కొలత_t అడ్డువరుసలు_లోపల_a,
  కొలత_t columns_లోపల_a,
  కొలత_t max_ones_లోపల_hint,
  కొలత_t commitment_hash_కొలత,
  కొలత_t బిట్లు_చొప్పున_gamma1_coefficient
)
{
  తిరిగి
    commitment_hash_కొలత +
      columns_లోపల_a * libcrux_ml_dsa_constants_gamma1_ring_element_కొలత(బిట్లు_చొప్పున_gamma1_coefficient)
    + max_ones_లోపల_hint
    + అడ్డువరుసలు_లోపల_a;
}

స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_constants_signing_కీలకం_కొలత(
  కొలత_t అడ్డువరుసలు_లోపల_a,
  కొలత_t columns_లోపల_a,
  కొలత_t error_ring_element_కొలత
)
{
  తిరిగి
    LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత + LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_SIGNING_కొలత +
      LIBCRUX_ML_DSA_CONSTANTS_బైట్లు_FOR_VERIFICATION_కీలకం_HASH
    + (అడ్డువరుసలు_లోపల_a + columns_లోపల_a) * error_ring_element_కొలత
    + అడ్డువరుసలు_లోపల_a * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T0_S_కొలత;
}

స్థిర అంతఃవరుస కొలత_t libcrux_ml_dsa_constants_verification_కీలకం_కొలత(కొలత_t అడ్డువరుసలు_లోపల_a)
{
  తిరిగి
    LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత +
      LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * అడ్డువరుసలు_లోపల_a *
        (LIBCRUX_ML_DSA_CONSTANTS_క్షేత్రం_MODULUS_MINUS_ONE_బిట్టు_నిడివి -
          LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_క్రింది_PART_యొక్క_T)
      / (కొలత_t)8U;
}

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_బిట్లు_చొప్పున_COMMITMENT_COEFFICIENT ((కొలత_t)6U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_బిట్లు_చొప్పున_ERROR_COEFFICIENT ((కొలత_t)3U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_బిట్లు_చొప్పున_GAMMA1_COEFFICIENT ((కొలత_t)18U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A ((కొలత_t)4U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_కొలత ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA (libcrux_ml_dsa_constants_Eta_Two)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT ((కొలత_t)17U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_క్షేత్రం_MODULUS - 1) / 88)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_లోపల_HINT ((కొలత_t)80U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_లోపల_VERIFIER_CHALLENGE ((కొలత_t)39U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A ((కొలత_t)4U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_బిట్లు_చొప్పున_COMMITMENT_COEFFICIENT ((కొలత_t)4U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_బిట్లు_చొప్పున_ERROR_COEFFICIENT ((కొలత_t)4U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_బిట్లు_చొప్పున_GAMMA1_COEFFICIENT ((కొలత_t)20U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A ((కొలత_t)5U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_కొలత ((కొలత_t)48U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA (libcrux_ml_dsa_constants_Eta_Four)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT ((కొలత_t)19U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_క్షేత్రం_MODULUS - 1) / 32)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_లోపల_HINT ((కొలత_t)55U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_లోపల_VERIFIER_CHALLENGE ((కొలత_t)49U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A ((కొలత_t)6U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_బిట్లు_చొప్పున_COMMITMENT_COEFFICIENT ((కొలత_t)4U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_బిట్లు_చొప్పున_ERROR_COEFFICIENT ((కొలత_t)3U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_బిట్లు_చొప్పున_GAMMA1_COEFFICIENT ((కొలత_t)20U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A ((కొలత_t)7U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_కొలత ((కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA (libcrux_ml_dsa_constants_Eta_Two)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT ((కొలత_t)19U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_క్షేత్రం_MODULUS - 1) / 32)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_లోపల_HINT ((కొలత_t)75U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_లోపల_VERIFIER_CHALLENGE ((కొలత_t)60U)

#నిర్వచించు LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A ((కొలత_t)8U)

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::constants::Eta}
*/
స్థిర అంతఃవరుస libcrux_ml_dsa_constants_Eta
libcrux_ml_dsa_constants_clone_54(స్థిరరాశి libcrux_ml_dsa_constants_Eta *self)
{
  తిరిగి self[0U];
}

స్థిర KRML_MUSTINLINE కొలత_t
libcrux_ml_dsa_encoding_error_chunk_కొలత(libcrux_ml_dsa_constants_Eta eta)
{
  ఎంపిక (eta)
  {
    స్థితి libcrux_ml_dsa_constants_Eta_Two:
      {
        ఆపు;
      }
    స్థితి libcrux_ml_dsa_constants_Eta_Four:
      {
        తిరిగి (కొలత_t)4U;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  తిరిగి (కొలత_t)3U;
}

#నిర్వచించు libcrux_ml_dsa_types_VerificationError_MalformedHintError 0
#నిర్వచించు libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError 1
#నిర్వచించు libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_సరిపోలిక_Error 2
#నిర్వచించు libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError 3

రకనిర్వచనం uint8_t libcrux_ml_dsa_types_VerificationError;

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_signature_సమితి_hint(
  Eurydice_dst_ref_mut_20 బహిర్గతం_hint,
  కొలత_t i,
  కొలత_t j
)
{
  బహిర్గతం_hint.ptr[i].దత్తాంశం[j] = 1;
}

#నిర్వచించు LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_బైట్లు_చొప్పున_SIMD_UNIT ((కొలత_t)13U)

#నిర్వచించు LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_కిటికీ ((కొలత_t)10U)

#నిర్వచించు LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_బైట్లు_చొప్పున_SIMD_UNIT ((కొలత_t)10U)

#నిర్వచించు LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_ఖండం_కొలత ((కొలత_t)168U)

#నిర్వచించు LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_FIVE_ఖండాలు_కొలత (LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_ఖండం_కొలత * (కొలత_t)5U)

#నిర్వచించు LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE256_ఖండం_కొలత ((కొలత_t)136U)

స్థిర KRML_MUSTINLINE Eurydice_arr_91
libcrux_ml_dsa_sample_కూడు_error_domain_separator(
  Eurydice_borrow_ముక్క_u8 ముక్క,
  uint16_t domain_separator
)
{
  Eurydice_arr_91 బహిర్గతం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d4(&బహిర్గతం,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = ముక్క.meta })),
    ముక్క,
    uint8_t);
  బహిర్గతం.దత్తాంశం[64U] = (uint8_t)(uint32_t)domain_separator;
  బహిర్గతం.దత్తాంశం[65U] = (uint8_t)((uint32_t)domain_separator >> 8U & 0xFFFFU);
  తిరిగి బహిర్గతం;
}

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_కొలత (libcrux_ml_dsa_constants_error_ring_element_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_బిట్లు_చొప్పున_ERROR_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_TRAITS_క్షేత్రం_MODULUS (8380417)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_యొక్క_MODULUS_MOD_MONTGOMERY_R (58728449ULL)

స్థిర అంతఃవరుస uint8_t_x2
libcrux_ml_dsa_sample_sample_పైకి_గమ్యం_four_ring_elements_flat_xy(కొలత_t index, కొలత_t వెడల్పు)
{
  తిరిగి
    (KRML_CLITERAL(uint8_t_x2){ .fst = (uint8_t)(index / వెడల్పు), .snd = (uint8_t)(index % వెడల్పు) });
}

స్థిర KRML_MUSTINLINE uint16_t libcrux_ml_dsa_sample_generate_domain_separator(uint8_t_x2 _)
{
  uint8_t అడ్డువరుస = _.fst;
  uint8_t స్తంభం = _.snd;
  తిరిగి (uint32_t)(uint16_t)(uint32_t)స్తంభం | (uint32_t)(uint16_t)(uint32_t)అడ్డువరుస << 8U;
}

స్థిర KRML_MUSTINLINE Eurydice_arr_31
libcrux_ml_dsa_sample_కూడు_domain_separator(Eurydice_borrow_ముక్క_u8 ముక్క, uint8_t_x2 indices)
{
  Eurydice_arr_31 బహిర్గతం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d40(&బహిర్గతం,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = ముక్క.meta })),
    ముక్క,
    uint8_t);
  uint16_t domain_separator = libcrux_ml_dsa_sample_generate_domain_separator(indices);
  బహిర్గతం.దత్తాంశం[32U] = (uint8_t)(uint32_t)domain_separator;
  బహిర్గతం.దత్తాంశం[33U] = (uint8_t)((uint32_t)domain_separator >> 8U & 0xFFFFU);
  తిరిగి బహిర్గతం;
}

#నిర్వచించు libcrux_ml_dsa_types_SigningError_RejectionSamplingError 0
#నిర్వచించు libcrux_ml_dsa_types_SigningError_ContextTooLongError 1

రకనిర్వచనం uint8_t libcrux_ml_dsa_types_SigningError;

రకనిర్వచనం నిర్మాణం libcrux_ml_dsa_pre_hash_DomainSeparationContext_s
{
  Eurydice_borrow_ముక్క_u8 context;
  core_option_Option_57 pre_hash_oid;
}
libcrux_ml_dsa_pre_hash_DomainSeparationContext;

#నిర్వచించు libcrux_ml_dsa_pre_hash_DomainSeparationError_ContextTooLongError 0

రకనిర్వచనం uint8_t libcrux_ml_dsa_pre_hash_DomainSeparationError;

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext, libcrux_ml_dsa_pre_hash_DomainSeparationError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_a8_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  సంఘం {
    libcrux_ml_dsa_pre_hash_DomainSeparationContext case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationError case_Err;
  }
  val;
}
core_ఫలితం_ఫలితం_a8;

/**
 `context` must be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_a8
libcrux_ml_dsa_pre_hash_new_88(
  Eurydice_borrow_ముక్క_u8 context,
  core_option_Option_57 pre_hash_oid
)
{
  ఒకవేళ (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_a8){
          .ట్యాగ్ = core_ఫలితం_Ok,
          .val = { .case_Ok = { .context = context, .pre_hash_oid = pre_hash_oid } }
        }
      );
  }
  తిరిగి
    (
      KRML_CLITERAL(core_ఫలితం_ఫలితం_a8){
        .ట్యాగ్ = core_ఫలితం_Err,
        .val = { .case_Err = libcrux_ml_dsa_pre_hash_DomainSeparationError_ContextTooLongError }
      }
    );
}

/**
 Returns the pre-hash OID, if any.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
స్థిర అంతఃవరుస స్థిరరాశి
core_option_Option_57
*libcrux_ml_dsa_pre_hash_pre_hash_oid_88(
  స్థిరరాశి libcrux_ml_dsa_pre_hash_DomainSeparationContext *self
)
{
  తిరిగి &self->pre_hash_oid;
}

/**
 Returns the context, guaranteed to be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
స్థిర అంతఃవరుస Eurydice_borrow_ముక్క_u8
libcrux_ml_dsa_pre_hash_context_88(స్థిరరాశి libcrux_ml_dsa_pre_hash_DomainSeparationContext *self)
{
  తిరిగి self->context;
}

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_కొలత (libcrux_ml_dsa_constants_commitment_ring_element_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_బిట్లు_చొప్పున_COMMITMENT_COEFFICIENT))

స్థిర KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_inside_బహిర్గతం_shuffle(
  Eurydice_borrow_ముక్క_u8 randomness,
  కొలత_t *బహిర్గతం_సూచీ,
  uint64_t *signs,
  Eurydice_arr_6c *ఫలితం
)
{
  bool పూర్తి = false;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < randomness.meta; i++)
  {
    కొలత_t _cloop_j = i;
    స్థిరరాశి uint8_t *byte = &randomness.ptr[_cloop_j];
    ఒకవేళ (!పూర్తి)
    {
      కొలత_t sample_at = (కొలత_t)(uint32_t)byte[0U];
      ఒకవేళ (sample_at <= బహిర్గతం_సూచీ[0U])
      {
        ఫలితం->దత్తాంశం[బహిర్గతం_సూచీ[0U]] = ఫలితం->దత్తాంశం[sample_at];
        బహిర్గతం_సూచీ[0U]++;
        ఫలితం->దత్తాంశం[sample_at] = 1 - 2 * (int32_t)(signs[0U] & 1ULL);
        signs[0U] >>= 1U;
      }
      పూర్తి = బహిర్గతం_సూచీ[0U] == (కొలత_t)256U;
    }
  }
  తిరిగి పూర్తి;
}

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_లోపల_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_కొలత (libcrux_ml_dsa_constants_gamma1_ring_element_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_బిట్లు_చొప్పున_GAMMA1_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID ((KRML_CLITERAL(Eurydice_arr_c9){ .దత్తాంశం = { 6U, 9U, 96U, 134U, 72U, 1U, 101U, 3U, 4U, 2U, 11U } }))

/**
This function found in impl {libcrux_ml_dsa::pre_hash::PreHash for libcrux_ml_dsa::pre_hash::SHAKE128_PH}
*/
స్థిర అంతఃవరుస Eurydice_arr_c9 libcrux_ml_dsa_pre_hash_oid_30(శూన్య)
{
  తిరిగి LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID;
}

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_VERIFICATION_కీలకం_కొలత (libcrux_ml_dsa_constants_verification_కీలకం_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNATURE_కొలత (libcrux_ml_dsa_constants_signature_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_లోపల_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_కొలత, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_బిట్లు_చొప్పున_GAMMA1_COEFFICIENT))

రకనిర్వచనం Eurydice_arr_4d libcrux_ml_dsa_simd_portable_సదిశ_type_Coefficients;

స్థిర KRML_MUSTINLINE Eurydice_arr_4d libcrux_ml_dsa_simd_portable_సదిశ_type_zero(శూన్య)
{
  తిరిగి (KRML_CLITERAL(Eurydice_arr_4d){ .దత్తాంశం = { 0U } });
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస Eurydice_arr_4d libcrux_ml_dsa_simd_portable_zero_65(శూన్య)
{
  తిరిగి libcrux_ml_dsa_simd_portable_సదిశ_type_zero();
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_సదిశ_type_from_coefficient_array(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_4d *బహిర్గతం
)
{
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_fd(బహిర్గతం),
    Eurydice_ముక్క_subslice_shared_47(array,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)0U,
          .చివర = LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_లోపల_SIMD_UNIT
        }
      )),
    int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_from_coefficient_array_65(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_4d *బహిర్గతం
)
{
  libcrux_ml_dsa_simd_portable_సదిశ_type_from_coefficient_array(array, బహిర్గతం);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_సదిశ_type_గమ్యం_coefficient_array(
  స్థిరరాశి Eurydice_arr_4d *విలువ,
  Eurydice_dst_ref_mut_83 బహిర్గతం
)
{
  Eurydice_ముక్క_copy(బహిర్గతం, Eurydice_array_గమ్యం_ముక్క_shared_fd(విలువ), int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_గమ్యం_coefficient_array_65(
  స్థిరరాశి Eurydice_arr_4d *విలువ,
  Eurydice_dst_ref_mut_83 బహిర్గతం
)
{
  libcrux_ml_dsa_simd_portable_సదిశ_type_గమ్యం_coefficient_array(విలువ, బహిర్గతం);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_arithmetic_కూడు(Eurydice_arr_4d *lhs, స్థిరరాశి Eurydice_arr_4d *rhs)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    కొలత_t uu____0 = i0;
    lhs->దత్తాంశం[uu____0] += rhs->దత్తాంశం[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_కూడు_65(Eurydice_arr_4d *lhs, స్థిరరాశి Eurydice_arr_4d *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_కూడు(lhs, rhs);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(
  Eurydice_arr_4d *lhs,
  స్థిరరాశి Eurydice_arr_4d *rhs
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    కొలత_t uu____0 = i0;
    lhs->దత్తాంశం[uu____0] -= rhs->దత్తాంశం[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_వ్యవకలనం_65(Eurydice_arr_4d *lhs, స్థిరరాశి Eurydice_arr_4d *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(lhs, rhs);
}

స్థిర KRML_MUSTINLINE bool
libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  int32_t bound
)
{
  bool ఫలితం = false;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    int32_t coefficient = simd_unit->దత్తాంశం[i0];
    int32_t sign = coefficient >> 31U;
    int32_t normalized = coefficient - (sign & 2 * coefficient);
    bool uu____0;
    ఒకవేళ (ఫలితం)
    {
      uu____0 = true;
    }
    లేకపోతే
    {
      uu____0 = normalized >= bound;
    }
    ఫలితం = uu____0;
  }
  తిరిగి ఫలితం;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస bool
libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  int32_t bound
)
{
  తిరిగి libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(simd_unit, bound);
}

స్థిర KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(int32_t gamma2, int32_t r)
{
  int32_t r0 = r + (r >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_క్షేత్రం_MODULUS);
  int32_t ceil_యొక్క_r_by_128 = (r0 + 127) >> 7U;
  int32_t r1;
  ఎంపిక (gamma2)
  {
    స్థితి 95232:
      {
        int32_t ఫలితం = (ceil_యొక్క_r_by_128 * 11275 + (int32_t)((uint32_t)1 << 23U)) >> 24U;
        int32_t ఫలితం_0 = (ఫలితం ^ (43 - ఫలితం) >> 31U) & ఫలితం;
        r1 = ఫలితం_0;
        ఆపు;
      }
    స్థితి 261888:
      {
        int32_t ఫలితం = (ceil_యొక్క_r_by_128 * 1025 + (int32_t)((uint32_t)1 << 21U)) >> 22U;
        int32_t ఫలితం_0 = ఫలితం & 15;
        r1 = ఫలితం_0;
        ఆపు;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  int32_t alpha = gamma2 * 2;
  int32_t r00 = r0 - r1 * alpha;
  r00 -=
    ((LIBCRUX_ML_DSA_SIMD_TRAITS_క్షేత్రం_MODULUS - 1) / 2 - r00) >> 31U &
      LIBCRUX_ML_DSA_SIMD_TRAITS_క్షేత్రం_MODULUS;
  తిరిగి (KRML_CLITERAL(int32_t_x2){ .fst = r00, .snd = r1 });
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_arithmetic_decompose(
  int32_t gamma2,
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *దిగువ,
  Eurydice_arr_4d *ఎగువ
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    int32_t_x2
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2,
        simd_unit->దత్తాంశం[i0]);
    int32_t uu____1 = uu____0.snd;
    దిగువ->దత్తాంశం[i0] = uu____0.fst;
    ఎగువ->దత్తాంశం[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_decompose_65(
  int32_t gamma2,
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *దిగువ,
  Eurydice_arr_4d *ఎగువ
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_decompose(gamma2, simd_unit, దిగువ, ఎగువ);
}

స్థిర KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(
  int32_t దిగువ,
  int32_t ఎగువ,
  int32_t gamma2
)
{
  int32_t uu____0;
  ఒకవేళ (దిగువ > gamma2)
  {
    uu____0 = 1;
  }
  లేకపోతే ఒకవేళ (దిగువ < -gamma2)
  {
    uu____0 = 1;
  }
  లేకపోతే ఒకవేళ (దిగువ == -gamma2)
  {
    ఒకవేళ (ఎగువ != 0)
    {
      uu____0 = 1;
    }
    లేకపోతే
    {
      uu____0 = 0;
    }
  }
  లేకపోతే
  {
    uu____0 = 0;
  }
  తిరిగి uu____0;
}

స్థిర KRML_MUSTINLINE కొలత_t
libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(
  స్థిరరాశి Eurydice_arr_4d *దిగువ,
  స్థిరరాశి Eurydice_arr_4d *ఎగువ,
  int32_t gamma2,
  Eurydice_arr_4d *hint
)
{
  కొలత_t one_hints_లెక్క = (కొలత_t)0U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    hint->దత్తాంశం[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(దిగువ->దత్తాంశం[i0],
        ఎగువ->దత్తాంశం[i0],
        gamma2);
    one_hints_లెక్క += (కొలత_t)hint->దత్తాంశం[i0];
  }
  తిరిగి one_hints_లెక్క;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_simd_portable_compute_hint_65(
  స్థిరరాశి Eurydice_arr_4d *దిగువ,
  స్థిరరాశి Eurydice_arr_4d *ఎగువ,
  int32_t gamma2,
  Eurydice_arr_4d *hint
)
{
  తిరిగి libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(దిగువ, ఎగువ, gamma2, hint);
}

స్థిర KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(int32_t gamma2, int32_t r, int32_t hint)
{
  int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2, r);
  int32_t r0 = uu____0.fst;
  int32_t r1 = uu____0.snd;
  int32_t uu____1;
  ఒకవేళ (!(hint == 0))
  {
    ఎంపిక (gamma2)
    {
      స్థితి 95232:
        {
          ఒకవేళ (r0 > 0)
          {
            ఒకవేళ (r1 == 43)
            {
              uu____1 = 0;
            }
            లేకపోతే
            {
              uu____1 = r1 + hint;
            }
          }
          లేకపోతే ఒకవేళ (r1 == 0)
          {
            uu____1 = 43;
          }
          లేకపోతే
          {
            uu____1 = r1 - hint;
          }
          ఆపు;
        }
      స్థితి 261888:
        {
          ఒకవేళ (r0 > 0)
          {
            uu____1 = (r1 + hint) & 15;
          }
          లేకపోతే
          {
            uu____1 = (r1 - hint) & 15;
          }
          ఆపు;
        }
      అప్రమేయ:
        {
          KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
          KRML_HOST_EXIT(255U);
        }
    }
    తిరిగి uu____1;
  }
  తిరిగి r1;
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_arithmetic_use_hint(
  int32_t gamma2,
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *hint
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    int32_t
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(gamma2,
        simd_unit->దత్తాంశం[i0],
        hint->దత్తాంశం[i0]);
    hint->దత్తాంశం[i0] = uu____0;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_use_hint_65(
  int32_t gamma2,
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *hint
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_use_hint(gamma2, simd_unit, hint);
}

స్థిర KRML_MUSTINLINE uint64_t
libcrux_ml_dsa_simd_portable_arithmetic_get_n_కనిష్ఠ_significant_బిట్లు(uint8_t n, uint64_t విలువ)
{
  తిరిగి విలువ & ((1ULL << (uint32_t)n) - 1ULL);
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_జరుపు (32U)

స్థిర KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element(int64_t విలువ)
{
  uint64_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_get_n_కనిష్ఠ_significant_బిట్లు(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_జరుపు,
      (uint64_t)విలువ)
    * LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_యొక్క_MODULUS_MOD_MONTGOMERY_R;
  int32_t
  k =
    (int32_t)libcrux_ml_dsa_simd_portable_arithmetic_get_n_కనిష్ఠ_significant_బిట్లు(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_జరుపు,
      t);
  int64_t k_times_modulus = (int64_t)k * (int64_t)LIBCRUX_ML_DSA_SIMD_TRAITS_క్షేత్రం_MODULUS;
  int32_t
  c =
    (int32_t)(k_times_modulus >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_జరుపు);
  int32_t
  విలువ_ఎగువ =
    (int32_t)(విలువ >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_జరుపు);
  తిరిగి విలువ_ఎగువ - c;
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(
  Eurydice_arr_4d *lhs,
  స్థిరరాశి Eurydice_arr_4d *rhs
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    lhs->దత్తాంశం[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)lhs->దత్తాంశం[i0] *
          (int64_t)rhs->దత్తాంశం[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_montgomery_multiply_65(
  Eurydice_arr_4d *lhs,
  స్థిరరాశి Eurydice_arr_4d *rhs
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(lhs, rhs);
}

స్థిర KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_element(int32_t fe)
{
  int32_t quotient = (fe + (int32_t)((uint32_t)1 << 22U)) >> 23U;
  తిరిగి fe - quotient * LIBCRUX_ML_DSA_SIMD_TRAITS_క్షేత్రం_MODULUS;
}

స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(Eurydice_arr_4d *simd_unit)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    simd_unit->దత్తాంశం[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_element(simd_unit->దత్తాంశం[i0]);
  }
}

స్థిర KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(int32_t t)
{
  int32_t t2 = t + (t >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_క్షేత్రం_MODULUS);
  int32_t
  t1 =
    (t2 - 1 +
      (int32_t)((uint32_t)1 <<
        (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_క్రింది_PART_యొక్క_T - (కొలత_t)1U)))
    >> (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_క్రింది_PART_యొక్క_T;
  int32_t
  t0 = t2 - (int32_t)((uint32_t)t1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_క్రింది_PART_యొక్క_T);
  తిరిగి (KRML_CLITERAL(int32_t_x2){ .fst = t0, .snd = t1 });
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_arithmetic_power2round(Eurydice_arr_4d *t0, Eurydice_arr_4d *t1)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(t0->దత్తాంశం[i0]);
    int32_t uu____1 = uu____0.snd;
    t0->దత్తాంశం[i0] = uu____0.fst;
    t1->దత్తాంశం[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_power2round_65(Eurydice_arr_4d *t0, Eurydice_arr_4d *t1)
{
  libcrux_ml_dsa_simd_portable_arithmetic_power2round(t0, t1);
}

స్థిర KRML_MUSTINLINE కొలత_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_క్షేత్రం_modulus(
  Eurydice_borrow_ముక్క_u8 randomness,
  Eurydice_dst_ref_mut_83 బహిర్గతం
)
{
  కొలత_t sampled = (కొలత_t)0U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < randomness.meta / (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    int32_t b0 = (int32_t)(uint32_t)randomness.ptr[i0 * (కొలత_t)3U];
    int32_t b1 = (int32_t)(uint32_t)randomness.ptr[i0 * (కొలత_t)3U + (కొలత_t)1U];
    int32_t b2 = (int32_t)(uint32_t)randomness.ptr[i0 * (కొలత_t)3U + (కొలత_t)2U];
    int32_t
    coefficient = (((int32_t)((uint32_t)b2 << 16U) | (int32_t)((uint32_t)b1 << 8U)) | b0) & 8388607;
    ఒకవేళ (coefficient < LIBCRUX_ML_DSA_CONSTANTS_క్షేత్రం_MODULUS)
    {
      బహిర్గతం.ptr[sampled] = coefficient;
      sampled++;
    }
  }
  తిరిగి sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_క్షేత్రం_modulus_65(
  Eurydice_borrow_ముక్క_u8 randomness,
  Eurydice_dst_ref_mut_83 బహిర్గతం
)
{
  తిరిగి
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_క్షేత్రం_modulus(randomness,
      బహిర్గతం);
}

స్థిర KRML_MUSTINLINE కొలత_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(
  Eurydice_borrow_ముక్క_u8 randomness,
  Eurydice_dst_ref_mut_83 బహిర్గతం
)
{
  కొలత_t sampled = (కొలత_t)0U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < randomness.meta; i++)
  {
    కొలత_t i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    bool try_0_comp = try_0 < 15U;
    bool try_1_comp = try_1 < 15U;
    ఒకవేళ (try_0_comp)
    {
      int32_t try_00 = (int32_t)(uint32_t)try_0;
      int32_t try_0_mod_5 = try_00 - (try_00 * 26 >> 7U) * 5;
      బహిర్గతం.ptr[sampled] = 2 - try_0_mod_5;
      sampled++;
    }
    ఒకవేళ (try_1_comp)
    {
      int32_t try_10 = (int32_t)(uint32_t)try_1;
      int32_t try_1_mod_5 = try_10 - (try_10 * 26 >> 7U) * 5;
      బహిర్గతం.ptr[sampled] = 2 - try_1_mod_5;
      sampled++;
    }
  }
  తిరిగి sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(
  Eurydice_borrow_ముక్క_u8 randomness,
  Eurydice_dst_ref_mut_83 బహిర్గతం
)
{
  తిరిగి
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(randomness,
      బహిర్గతం);
}

స్థిర KRML_MUSTINLINE కొలత_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(
  Eurydice_borrow_ముక్క_u8 randomness,
  Eurydice_dst_ref_mut_83 బహిర్గతం
)
{
  కొలత_t sampled = (కొలత_t)0U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < randomness.meta; i++)
  {
    కొలత_t i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    bool try_0_comp = try_0 < 9U;
    bool try_1_comp = try_1 < 9U;
    ఒకవేళ (try_0_comp)
    {
      బహిర్గతం.ptr[sampled] = 4 - (int32_t)(uint32_t)try_0;
      sampled++;
    }
    ఒకవేళ (try_1_comp)
    {
      బహిర్గతం.ptr[sampled] = 4 - (int32_t)(uint32_t)try_1;
      sampled++;
    }
  }
  తిరిగి sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస కొలత_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(
  Eurydice_borrow_ముక్క_u8 randomness,
  Eurydice_dst_ref_mut_83 బహిర్గతం
)
{
  తిరిగి
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(randomness,
      బహిర్గతం);
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)((uint32_t)1 << 19U))

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U / (కొలత_t)2U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_గమ్యం_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)2U,
            .చివర = i0 * (కొలత_t)2U + (కొలత_t)2U
          }
        ));
    int32_t
    coefficient0 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficients.ptr[0U];
    int32_t
    coefficient1 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficients.ptr[1U];
    serialized.ptr[(కొలత_t)5U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(కొలత_t)5U * i0 + (కొలత_t)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(కొలత_t)5U * i0 + (కొలత_t)2U] = (uint8_t)(coefficient0 >> 16U);
    కొలత_t uu____0 = (కొలత_t)5U * i0 + (కొలత_t)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 4U);
    serialized.ptr[(కొలత_t)5U * i0 + (కొలత_t)3U] = (uint8_t)(coefficient1 >> 4U);
    serialized.ptr[(కొలత_t)5U * i0 + (కొలత_t)4U] = (uint8_t)(coefficient1 >> 12U);
  }
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)((uint32_t)1 << 17U))

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_17(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U / (కొలత_t)4U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_గమ్యం_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)4U,
            .చివర = i0 * (కొలత_t)4U + (కొలత_t)4U
          }
        ));
    int32_t
    coefficient0 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[0U];
    int32_t
    coefficient1 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[1U];
    int32_t
    coefficient2 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[2U];
    int32_t
    coefficient3 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[3U];
    serialized.ptr[(కొలత_t)9U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(కొలత_t)9U * i0 + (కొలత_t)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(కొలత_t)9U * i0 + (కొలత_t)2U] = (uint8_t)(coefficient0 >> 16U);
    కొలత_t uu____0 = (కొలత_t)9U * i0 + (కొలత_t)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 2U);
    serialized.ptr[(కొలత_t)9U * i0 + (కొలత_t)3U] = (uint8_t)(coefficient1 >> 6U);
    serialized.ptr[(కొలత_t)9U * i0 + (కొలత_t)4U] = (uint8_t)(coefficient1 >> 14U);
    కొలత_t uu____1 = (కొలత_t)9U * i0 + (కొలత_t)4U;
    serialized.ptr[uu____1] =
      (uint32_t)serialized.ptr[uu____1] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient2 << 4U);
    serialized.ptr[(కొలత_t)9U * i0 + (కొలత_t)5U] = (uint8_t)(coefficient2 >> 4U);
    serialized.ptr[(కొలత_t)9U * i0 + (కొలత_t)6U] = (uint8_t)(coefficient2 >> 12U);
    కొలత_t uu____2 = (కొలత_t)9U * i0 + (కొలత_t)6U;
    serialized.ptr[uu____2] =
      (uint32_t)serialized.ptr[uu____2] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient3 << 6U);
    serialized.ptr[(కొలత_t)9U * i0 + (కొలత_t)7U] = (uint8_t)(coefficient3 >> 2U);
    serialized.ptr[(కొలత_t)9U * i0 + (కొలత_t)8U] = (uint8_t)(coefficient3 >> 10U);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized,
  కొలత_t gamma1_exponent
)
{
  ఎంపిక (gamma1_exponent)
  {
    స్థితి 17U:
      {
        ఆపు;
      }
    స్థితి 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(simd_unit,
          serialized);
        తిరిగి;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_17(simd_unit,
    serialized);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_gamma1_serialize_65(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized,
  కొలత_t gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(simd_unit, serialized, gamma1_exponent);
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)((uint32_t)1 << 19U))

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK ((int32_t)((uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 << 1U) - 1)

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < serialized.meta / (కొలత_t)5U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)5U,
            .చివర = i0 * (కొలత_t)5U + (కొలత_t)5U
          }
        ));
    int32_t coefficient0 = (int32_t)(uint32_t)బైట్లు.ptr[0U];
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[1U] << 8U);
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[2U] << 16U);
    coefficient0 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)(uint32_t)బైట్లు.ptr[2U] >> 4U;
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[3U] << 4U);
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[4U] << 12U);
    simd_unit->దత్తాంశం[(కొలత_t)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient0;
    simd_unit->దత్తాంశం[(కొలత_t)2U * i0 + (కొలత_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient1;
  }
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)((uint32_t)1 << 17U))

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK ((int32_t)((uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 << 1U) - 1)

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < serialized.meta / (కొలత_t)9U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)9U,
            .చివర = i0 * (కొలత_t)9U + (కొలత_t)9U
          }
        ));
    int32_t coefficient0 = (int32_t)(uint32_t)బైట్లు.ptr[0U];
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[1U] << 8U);
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[2U] << 16U);
    coefficient0 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)(uint32_t)బైట్లు.ptr[2U] >> 2U;
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[3U] << 6U);
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[4U] << 14U);
    coefficient1 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient2 = (int32_t)(uint32_t)బైట్లు.ptr[4U] >> 4U;
    coefficient2 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[5U] << 4U);
    coefficient2 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[6U] << 12U);
    coefficient2 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient3 = (int32_t)(uint32_t)బైట్లు.ptr[6U] >> 6U;
    coefficient3 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[7U] << 2U);
    coefficient3 |= (int32_t)((uint32_t)(int32_t)(uint32_t)బైట్లు.ptr[8U] << 10U);
    coefficient3 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    simd_unit->దత్తాంశం[(కొలత_t)4U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient0;
    simd_unit->దత్తాంశం[(కొలత_t)4U * i0 + (కొలత_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient1;
    simd_unit->దత్తాంశం[(కొలత_t)4U * i0 + (కొలత_t)2U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient2;
    simd_unit->దత్తాంశం[(కొలత_t)4U * i0 + (కొలత_t)3U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient3;
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *బహిర్గతం,
  కొలత_t gamma1_exponent
)
{
  ఎంపిక (gamma1_exponent)
  {
    స్థితి 17U:
      {
        ఆపు;
      }
    స్థితి 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(serialized,
          బహిర్గతం);
        తిరిగి;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(serialized,
    బహిర్గతం);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *బహిర్గతం,
  కొలత_t gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(serialized, బహిర్గతం, gamma1_exponent);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->దత్తాంశం[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->దత్తాంశం[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->దత్తాంశం[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->దత్తాంశం[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->దత్తాంశం[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->దత్తాంశం[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->దత్తాంశం[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->దత్తాంశం[7U];
  uint8_t byte0 = (uint32_t)coefficient1 << 4U | (uint32_t)coefficient0;
  uint8_t byte1 = (uint32_t)coefficient3 << 4U | (uint32_t)coefficient2;
  uint8_t byte2 = (uint32_t)coefficient5 << 4U | (uint32_t)coefficient4;
  uint8_t byte3 = (uint32_t)coefficient7 << 4U | (uint32_t)coefficient6;
  serialized.ptr[0U] = byte0;
  serialized.ptr[1U] = byte1;
  serialized.ptr[2U] = byte2;
  serialized.ptr[3U] = byte3;
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->దత్తాంశం[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->దత్తాంశం[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->దత్తాంశం[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->దత్తాంశం[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->దత్తాంశం[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->దత్తాంశం[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->దత్తాంశం[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->దత్తాంశం[7U];
  uint8_t byte0 = (uint32_t)coefficient1 << 6U | (uint32_t)coefficient0;
  uint8_t byte1 = (uint32_t)coefficient2 << 4U | (uint32_t)coefficient1 >> 2U;
  uint8_t byte2 = (uint32_t)coefficient3 << 2U | (uint32_t)coefficient2 >> 4U;
  uint8_t byte3 = (uint32_t)coefficient5 << 6U | (uint32_t)coefficient4;
  uint8_t byte4 = (uint32_t)coefficient6 << 4U | (uint32_t)coefficient5 >> 2U;
  uint8_t byte5 = (uint32_t)coefficient7 << 2U | (uint32_t)coefficient6 >> 4U;
  serialized.ptr[0U] = byte0;
  serialized.ptr[1U] = byte1;
  serialized.ptr[2U] = byte2;
  serialized.ptr[3U] = byte3;
  serialized.ptr[4U] = byte4;
  serialized.ptr[5U] = byte5;
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  ఎంపిక ((uint32_t)(uint8_t)serialized.meta)
  {
    స్థితి 4U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(simd_unit, serialized);
        ఆపు;
      }
    స్థితి 6U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(simd_unit, serialized);
        ఆపు;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_commitment_serialize_65(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(simd_unit, serialized);
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA (4)

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U / (కొలత_t)2U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_గమ్యం_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)2U,
            .చివర = i0 * (కొలత_t)2U + (కొలత_t)2U
          }
        ));
    uint8_t
    coefficient0 =
      (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA -
        coefficients.ptr[0U]);
    uint8_t
    coefficient1 =
      (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA -
        coefficients.ptr[1U]);
    serialized.ptr[i0] = (uint32_t)coefficient1 << 4U | (uint32_t)coefficient0;
  }
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA (2)

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_2(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  uint8_t
  coefficient0 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->దత్తాంశం[0U]);
  uint8_t
  coefficient1 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->దత్తాంశం[1U]);
  uint8_t
  coefficient2 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->దత్తాంశం[2U]);
  uint8_t
  coefficient3 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->దత్తాంశం[3U]);
  uint8_t
  coefficient4 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->దత్తాంశం[4U]);
  uint8_t
  coefficient5 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->దత్తాంశం[5U]);
  uint8_t
  coefficient6 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->దత్తాంశం[6U]);
  uint8_t
  coefficient7 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->దత్తాంశం[7U]);
  serialized.ptr[0U] =
    ((uint32_t)coefficient2 << 6U | (uint32_t)coefficient1 << 3U) | (uint32_t)coefficient0;
  serialized.ptr[1U] =
    (((uint32_t)coefficient5 << 7U | (uint32_t)coefficient4 << 4U) | (uint32_t)coefficient3 << 1U)
    | (uint32_t)coefficient2 >> 2U;
  serialized.ptr[2U] =
    ((uint32_t)coefficient7 << 5U | (uint32_t)coefficient6 << 2U) | (uint32_t)coefficient5 >> 1U;
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_error_serialize(
  libcrux_ml_dsa_constants_Eta eta,
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  ఎంపిక (eta)
  {
    స్థితి libcrux_ml_dsa_constants_Eta_Two:
      {
        ఆపు;
      }
    స్థితి libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(simd_unit, serialized);
        తిరిగి;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_2(simd_unit, serialized);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_error_serialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_serialize(eta, simd_unit, serialized);
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA (4)

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *simd_units
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < serialized.meta; i++)
  {
    కొలత_t i0 = i;
    స్థిరరాశి uint8_t *byte = &serialized.ptr[i0];
    uint8_t uu____0 = core_ops_బిట్టు_core_ops_బిట్టు_బిట్టు_And_u8_u8_for_0_u8_bitand(byte, 15U);
    simd_units->దత్తాంశం[(కొలత_t)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA -
        (int32_t)(uint32_t)uu____0;
    uint8_t uu____1 = core_ops_బిట్టు_core_ops_బిట్టు_Shr_i32_u8_for_0_u8_shr(byte, 4);
    simd_units->దత్తాంశం[(కొలత_t)2U * i0 + (కొలత_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA -
        (int32_t)(uint32_t)uu____1;
  }
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA (2)

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t byte0 = (int32_t)(uint32_t)serialized.ptr[0U];
  int32_t byte1 = (int32_t)(uint32_t)serialized.ptr[1U];
  int32_t byte2 = (int32_t)(uint32_t)serialized.ptr[2U];
  simd_unit->దత్తాంశం[0U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte0 & 7);
  simd_unit->దత్తాంశం[1U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte0 >> 3U & 7);
  simd_unit->దత్తాంశం[2U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte0 >> 6U | (int32_t)((uint32_t)byte1 << 2U)) & 7);
  simd_unit->దత్తాంశం[3U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte1 >> 1U & 7);
  simd_unit->దత్తాంశం[4U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte1 >> 4U & 7);
  simd_unit->దత్తాంశం[5U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte1 >> 7U | (int32_t)((uint32_t)byte2 << 1U)) & 7);
  simd_unit->దత్తాంశం[6U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte2 >> 2U & 7);
  simd_unit->దత్తాంశం[7U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte2 >> 5U & 7);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_error_deserialize(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *బహిర్గతం
)
{
  ఎంపిక (eta)
  {
    స్థితి libcrux_ml_dsa_constants_Eta_Two:
      {
        ఆపు;
      }
    స్థితి libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(serialized, బహిర్గతం);
        తిరిగి;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(serialized, బహిర్గతం);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_error_deserialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *బహిర్గతం
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize(eta, serialized, బహిర్గతం);
}

స్థిర KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(int32_t t0)
{
  తిరిగి
    (int32_t)((uint32_t)1 <<
      (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_క్రింది_PART_యొక్క_T - (కొలత_t)1U))
    - t0;
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_t0_serialize(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  int32_t
  coefficient0 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->దత్తాంశం[0U]);
  int32_t
  coefficient1 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->దత్తాంశం[1U]);
  int32_t
  coefficient2 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->దత్తాంశం[2U]);
  int32_t
  coefficient3 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->దత్తాంశం[3U]);
  int32_t
  coefficient4 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->దత్తాంశం[4U]);
  int32_t
  coefficient5 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->దత్తాంశం[5U]);
  int32_t
  coefficient6 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->దత్తాంశం[6U]);
  int32_t
  coefficient7 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->దత్తాంశం[7U]);
  serialized.ptr[0U] = (uint8_t)coefficient0;
  serialized.ptr[1U] =
    (uint32_t)(uint8_t)(coefficient0 >> 8U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 5U);
  serialized.ptr[2U] = (uint8_t)(coefficient1 >> 3U);
  serialized.ptr[3U] =
    (uint32_t)(uint8_t)(coefficient1 >> 11U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient2 << 2U);
  serialized.ptr[4U] =
    (uint32_t)(uint8_t)(coefficient2 >> 6U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient3 << 7U);
  serialized.ptr[5U] = (uint8_t)(coefficient3 >> 1U);
  serialized.ptr[6U] =
    (uint32_t)(uint8_t)(coefficient3 >> 9U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient4 << 4U);
  serialized.ptr[7U] = (uint8_t)(coefficient4 >> 4U);
  serialized.ptr[8U] =
    (uint32_t)(uint8_t)(coefficient4 >> 12U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient5 << 1U);
  serialized.ptr[9U] =
    (uint32_t)(uint8_t)(coefficient5 >> 7U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient6 << 6U);
  serialized.ptr[10U] = (uint8_t)(coefficient6 >> 2U);
  serialized.ptr[11U] =
    (uint32_t)(uint8_t)(coefficient6 >> 10U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient7 << 3U);
  serialized.ptr[12U] = (uint8_t)(coefficient7 >> 5U);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_t0_serialize_65(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_serialize(simd_unit, బహిర్గతం);
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_బిట్లు_లోపల_క్రింది_PART_యొక్క_T_ముసుగు ((int32_t)((uint32_t)1 << (uint32_t)(int32_t)LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_క్రింది_PART_యొక్క_T) - 1)

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t byte0 = (int32_t)(uint32_t)serialized.ptr[0U];
  int32_t byte1 = (int32_t)(uint32_t)serialized.ptr[1U];
  int32_t byte2 = (int32_t)(uint32_t)serialized.ptr[2U];
  int32_t byte3 = (int32_t)(uint32_t)serialized.ptr[3U];
  int32_t byte4 = (int32_t)(uint32_t)serialized.ptr[4U];
  int32_t byte5 = (int32_t)(uint32_t)serialized.ptr[5U];
  int32_t byte6 = (int32_t)(uint32_t)serialized.ptr[6U];
  int32_t byte7 = (int32_t)(uint32_t)serialized.ptr[7U];
  int32_t byte8 = (int32_t)(uint32_t)serialized.ptr[8U];
  int32_t byte9 = (int32_t)(uint32_t)serialized.ptr[9U];
  int32_t byte10 = (int32_t)(uint32_t)serialized.ptr[10U];
  int32_t byte11 = (int32_t)(uint32_t)serialized.ptr[11U];
  int32_t byte12 = (int32_t)(uint32_t)serialized.ptr[12U];
  int32_t coefficient0 = byte0;
  coefficient0 |= (int32_t)((uint32_t)byte1 << 8U);
  coefficient0 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_బిట్లు_లోపల_క్రింది_PART_యొక్క_T_ముసుగు;
  int32_t coefficient1 = byte1 >> 5U;
  coefficient1 |= (int32_t)((uint32_t)byte2 << 3U);
  coefficient1 |= (int32_t)((uint32_t)byte3 << 11U);
  coefficient1 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_బిట్లు_లోపల_క్రింది_PART_యొక్క_T_ముసుగు;
  int32_t coefficient2 = byte3 >> 2U;
  coefficient2 |= (int32_t)((uint32_t)byte4 << 6U);
  coefficient2 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_బిట్లు_లోపల_క్రింది_PART_యొక్క_T_ముసుగు;
  int32_t coefficient3 = byte4 >> 7U;
  coefficient3 |= (int32_t)((uint32_t)byte5 << 1U);
  coefficient3 |= (int32_t)((uint32_t)byte6 << 9U);
  coefficient3 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_బిట్లు_లోపల_క్రింది_PART_యొక్క_T_ముసుగు;
  int32_t coefficient4 = byte6 >> 4U;
  coefficient4 |= (int32_t)((uint32_t)byte7 << 4U);
  coefficient4 |= (int32_t)((uint32_t)byte8 << 12U);
  coefficient4 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_బిట్లు_లోపల_క్రింది_PART_యొక్క_T_ముసుగు;
  int32_t coefficient5 = byte8 >> 1U;
  coefficient5 |= (int32_t)((uint32_t)byte9 << 7U);
  coefficient5 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_బిట్లు_లోపల_క్రింది_PART_యొక్క_T_ముసుగు;
  int32_t coefficient6 = byte9 >> 6U;
  coefficient6 |= (int32_t)((uint32_t)byte10 << 2U);
  coefficient6 |= (int32_t)((uint32_t)byte11 << 10U);
  coefficient6 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_బిట్లు_లోపల_క్రింది_PART_యొక్క_T_ముసుగు;
  int32_t coefficient7 = byte11 >> 3U;
  coefficient7 |= (int32_t)((uint32_t)byte12 << 5U);
  coefficient7 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_బిట్లు_లోపల_క్రింది_PART_యొక్క_T_ముసుగు;
  simd_unit->దత్తాంశం[0U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient0);
  simd_unit->దత్తాంశం[1U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient1);
  simd_unit->దత్తాంశం[2U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient2);
  simd_unit->దత్తాంశం[3U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient3);
  simd_unit->దత్తాంశం[4U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient4);
  simd_unit->దత్తాంశం[5U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient5);
  simd_unit->దత్తాంశం[6U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient6);
  simd_unit->దత్తాంశం[7U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient7);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_t0_deserialize_65(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *బహిర్గతం
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(serialized, బహిర్గతం);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_t1_serialize(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U / (కొలత_t)4U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_గమ్యం_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)4U,
            .చివర = i0 * (కొలత_t)4U + (కొలత_t)4U
          }
        ));
    serialized.ptr[(కొలత_t)5U * i0] = (uint8_t)(coefficients.ptr[0U] & 255);
    serialized.ptr[(కొలత_t)5U * i0 + (కొలత_t)1U] =
      (uint32_t)(uint8_t)(coefficients.ptr[1U] & 63) << 2U |
        (uint32_t)(uint8_t)(coefficients.ptr[0U] >> 8U & 3);
    serialized.ptr[(కొలత_t)5U * i0 + (కొలత_t)2U] =
      (uint32_t)(uint8_t)(coefficients.ptr[2U] & 15) << 4U |
        (uint32_t)(uint8_t)(coefficients.ptr[1U] >> 6U & 15);
    serialized.ptr[(కొలత_t)5U * i0 + (కొలత_t)3U] =
      (uint32_t)(uint8_t)(coefficients.ptr[3U] & 3) << 6U |
        (uint32_t)(uint8_t)(coefficients.ptr[2U] >> 4U & 63);
    serialized.ptr[(కొలత_t)5U * i0 + (కొలత_t)4U] = (uint8_t)(coefficients.ptr[3U] >> 2U & 255);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_t1_serialize_65(
  స్థిరరాశి Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_serialize(simd_unit, బహిర్గతం);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t
  ముసుగు = (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_బిట్లు_లోపల_పై_PART_యొక్క_T) - 1;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < serialized.meta / (కొలత_t)5U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)5U,
            .చివర = i0 * (కొలత_t)5U + (కొలత_t)5U
          }
        ));
    int32_t byte0 = (int32_t)(uint32_t)బైట్లు.ptr[0U];
    int32_t byte1 = (int32_t)(uint32_t)బైట్లు.ptr[1U];
    int32_t byte2 = (int32_t)(uint32_t)బైట్లు.ptr[2U];
    int32_t byte3 = (int32_t)(uint32_t)బైట్లు.ptr[3U];
    int32_t byte4 = (int32_t)(uint32_t)బైట్లు.ptr[4U];
    simd_unit->దత్తాంశం[(కొలత_t)4U * i0] = (byte0 | (int32_t)((uint32_t)byte1 << 8U)) & ముసుగు;
    simd_unit->దత్తాంశం[(కొలత_t)4U * i0 + (కొలత_t)1U] =
      (byte1 >> 2U | (int32_t)((uint32_t)byte2 << 6U)) & ముసుగు;
    simd_unit->దత్తాంశం[(కొలత_t)4U * i0 + (కొలత_t)2U] =
      (byte2 >> 4U | (int32_t)((uint32_t)byte3 << 4U)) & ముసుగు;
    simd_unit->దత్తాంశం[(కొలత_t)4U * i0 + (కొలత_t)3U] =
      (byte3 >> 6U | (int32_t)((uint32_t)byte4 << 2U)) & ముసుగు;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_t1_deserialize_65(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_4d *బహిర్గతం
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(serialized, బహిర్గతం);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_4d *simd_unit,
  int32_t c
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    simd_unit->దత్తాంశం[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)simd_unit->దత్తాంశం[i0]
        * (int64_t)c);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- $32size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_a3_s { Eurydice_arr_4d దత్తాంశం[32U]; } Eurydice_arr_a3;

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(
  Eurydice_arr_a3 *re,
  కొలత_t index,
  కొలత_t అడుగు_by,
  int32_t zeta
)
{
  Eurydice_arr_4d tmp = re->దత్తాంశం[index + అడుగు_by];
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&tmp, zeta);
  re->దత్తాంశం[index + అడుగు_by] = re->దత్తాంశం[index];
  libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[index + అడుగు_by], &tmp);
  libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[index], &tmp);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 16
- ZETA= 25847
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_30(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)16U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)16U, 25847);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_7(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_30(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 8
- ZETA= -2608894
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_300(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)8U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)8U, -2608894);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 8
- ZETA= -518909
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_42(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)16U; i < (కొలత_t)16U + (కొలత_t)8U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)8U, -518909);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_6(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_300(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_42(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 4
- ZETA= 237124
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_301(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)4U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)4U, 237124);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 4
- ZETA= -777960
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_82(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)8U; i < (కొలత_t)8U + (కొలత_t)4U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)4U, -777960);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 4
- ZETA= -876248
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_420(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)16U; i < (కొలత_t)16U + (కొలత_t)4U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)4U, -876248);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 4
- ZETA= 466468
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)24U; i < (కొలత_t)24U + (కొలత_t)4U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)4U, 466468);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_5(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_301(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_82(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_420(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 2
- ZETA= 1826347
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_302(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)2U, 1826347);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 2
- ZETA= 2353451
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_43(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)4U; i < (కొలత_t)4U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)2U, 2353451);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 2
- ZETA= -359251
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_820(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)8U; i < (కొలత_t)8U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)2U, -359251);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 2
- ZETA= -2091905
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)12U; i < (కొలత_t)12U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)2U, -2091905);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 2
- ZETA= 3119733
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_421(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)16U; i < (కొలత_t)16U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)2U, 3119733);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 2
- ZETA= -2884855
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_61(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)20U; i < (కొలత_t)20U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)2U, -2884855);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 2
- ZETA= 3111497
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe0(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)24U; i < (కొలత_t)24U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)2U, 3111497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 2
- ZETA= 2680103
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_38(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)28U; i < (కొలత_t)28U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)2U, 2680103);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_4(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_302(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_43(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_820(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_421(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_61(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe0(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_38(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 1
- ZETA= 2725464
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_303(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, 2725464);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 2
- STEP_BY= 1
- ZETA= 1024112
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_25(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)2U; i < (కొలత_t)2U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, 1024112);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 1
- ZETA= -1079900
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_430(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)4U; i < (కొలత_t)4U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, -1079900);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 6
- STEP_BY= 1
- ZETA= 3585928
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_f4(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)6U; i < (కొలత_t)6U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, 3585928);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 1
- ZETA= -549488
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_821(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)8U; i < (కొలత_t)8U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, -549488);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 10
- STEP_BY= 1
- ZETA= -1119584
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1d(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)10U; i < (కొలత_t)10U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, -1119584);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 1
- ZETA= 2619752
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea0(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)12U; i < (కొలత_t)12U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, 2619752);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 14
- STEP_BY= 1
- ZETA= -2108549
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d8(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)14U; i < (కొలత_t)14U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, -2108549);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 1
- ZETA= -2118186
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_422(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)16U; i < (కొలత_t)16U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, -2118186);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 18
- STEP_BY= 1
- ZETA= -3859737
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_60(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)18U; i < (కొలత_t)18U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, -3859737);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 1
- ZETA= -1399561
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_610(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)20U; i < (కొలత_t)20U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, -1399561);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 22
- STEP_BY= 1
- ZETA= -3277672
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_29(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)22U; i < (కొలత_t)22U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, -3277672);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 1
- ZETA= 1757237
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe1(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)24U; i < (కొలత_t)24U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, 1757237);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 26
- STEP_BY= 1
- ZETA= -19422
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_9d(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)26U; i < (కొలత_t)26U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, -19422);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 1
- ZETA= 4010497
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_380(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)28U; i < (కొలత_t)28U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, 4010497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 30
- STEP_BY= 1
- ZETA= 280005
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_5f(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)30U; i < (కొలత_t)30U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_విడత(re, j, (కొలత_t)1U, 280005);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_3(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_303(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_25(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_430(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_f4(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_821(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1d(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea0(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d8(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_422(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_60(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_610(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_29(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe1(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_9d(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_380(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_5f(re);
}

స్థిర KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(int32_t fe, int32_t fer)
{
  తిరిగి
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)fe * (int64_t)fer);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta,
  కొలత_t index,
  కొలత_t అడుగు
)
{
  int32_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(simd_unit->దత్తాంశం[index +
        అడుగు],
      zeta);
  simd_unit->దత్తాంశం[index + అడుగు] = simd_unit->దత్తాంశం[index] - t;
  simd_unit->దత్తాంశం[index] += t;
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta, (కొలత_t)0U, (కొలత_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta, (కొలత_t)1U, (కొలత_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta, (కొలత_t)2U, (కొలత_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta, (కొలత_t)3U, (కొలత_t)4U);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(
  Eurydice_arr_a3 *re,
  కొలత_t index,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(&re->దత్తాంశం[index], zeta);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)0U, 2706023);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)1U, 95776);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)2U, 3077325);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)3U, 3530437);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)4U, -1661693);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)5U, -3592148);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)6U, -2537516);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)7U, 3915439);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)8U, -3861115);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)9U, -3043716);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)10U, 3574422);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)11U, -2867647);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)12U, 3539968);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)13U, -300467);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)14U, 2348700);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)15U, -539299);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)16U, -1699267);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)17U, -1643818);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)18U, 3505694);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)19U, -3821735);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)20U, 3507263);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)21U, -2140649);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)22U, -1600420);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)23U, 3699596);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)24U, 811944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)25U, 531354);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)26U, 954230);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)27U, 3881043);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)28U, 3900724);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)29U, -2556880);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)30U, 2071892);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_విడత(re, (కొలత_t)31U, -2797779);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta1,
  int32_t zeta2
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta1, (కొలత_t)0U, (కొలత_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta1, (కొలత_t)1U, (కొలత_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta2, (కొలత_t)4U, (కొలత_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta2, (కొలత_t)5U, (కొలత_t)2U);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(
  Eurydice_arr_a3 *re,
  కొలత_t index,
  int32_t zeta_0,
  int32_t zeta_1
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(&re->దత్తాంశం[index], zeta_0, zeta_1);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)0U, -3930395, -1528703);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)1U, -3677745, -3041255);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)2U, -1452451, 3475950);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)3U, 2176455, -1585221);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)4U, -1257611, 1939314);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)5U, -4083598, -1000202);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)6U, -3190144, -3157330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)7U, -3632928, 126922);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)8U, 3412210, -983419);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)9U, 2147896, 2715295);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)10U, -2967645, -3693493);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)11U, -411027, -2477047);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)12U, -671102, -1228525);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)13U, -22981, -1308169);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)14U, -381987, 1349076);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)15U, 1852771, -1430430);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)16U, -3343383, 264944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)17U, 508951, 3097992);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)18U, 44288, -1100098);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)19U, 904516, 3958618);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)20U, -3724342, -8578);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)21U, 1653064, -3249728);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)22U, 2389356, -210977);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)23U, 759969, -1316856);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)24U, 189548, -3553272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)25U, 3159746, -1851402);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)26U, -2409325, -177440);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)27U, 1315589, 1341330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)28U, 1285669, -1584928);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)29U, -812732, -1439742);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)30U, -3019102, -3881060);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_విడత(re, (కొలత_t)31U, -3628969, 3839961);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta0, (కొలత_t)0U, (కొలత_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta1, (కొలత_t)2U, (కొలత_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta2, (కొలత_t)4U, (కొలత_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_అడుగు(simd_unit, zeta3, (కొలత_t)6U, (కొలత_t)1U);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(
  Eurydice_arr_a3 *re,
  కొలత_t index,
  int32_t zeta_0,
  int32_t zeta_1,
  int32_t zeta_2,
  int32_t zeta_3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(&re->దత్తాంశం[index],
    zeta_0,
    zeta_1,
    zeta_2,
    zeta_3);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)0U,
    2091667,
    3407706,
    2316500,
    3817976);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)1U,
    -3342478,
    2244091,
    -2446433,
    -3562462);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)2U,
    266997,
    2434439,
    -1235728,
    3513181);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)3U,
    -3520352,
    -3759364,
    -1197226,
    -3193378);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)4U,
    900702,
    1859098,
    909542,
    819034);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)5U,
    495491,
    -1613174,
    -43260,
    -522500);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)6U,
    -655327,
    -3122442,
    2031748,
    3207046);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)7U,
    -3556995,
    -525098,
    -768622,
    -3595838);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)8U,
    342297,
    286988,
    -2437823,
    4108315);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)9U,
    3437287,
    -3342277,
    1735879,
    203044);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)10U,
    2842341,
    2691481,
    -2590150,
    1265009);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)11U,
    4055324,
    1247620,
    2486353,
    1595974);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)12U,
    -3767016,
    1250494,
    2635921,
    -3548272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)13U,
    -2994039,
    1869119,
    1903435,
    -1050970);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)14U,
    -1333058,
    1237275,
    -3318210,
    -1430225);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)15U,
    -451100,
    1312455,
    3306115,
    -1962642);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)16U,
    -1279661,
    1917081,
    -2546312,
    -1374803);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)17U,
    1500165,
    777191,
    2235880,
    3406031);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)18U,
    -542412,
    -2831860,
    -1671176,
    -1846953);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)19U,
    -2584293,
    -3724270,
    594136,
    -3776993);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)20U,
    -2013608,
    2432395,
    2454455,
    -164721);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)21U,
    1957272,
    3369112,
    185531,
    -1207385);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)22U,
    -3183426,
    162844,
    1616392,
    3014001);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)23U,
    810149,
    1652634,
    -3694233,
    -1799107);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)24U,
    -3038916,
    3523897,
    3866901,
    269760);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)25U,
    2213111,
    -975884,
    1717735,
    472078);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)26U,
    -426683,
    1723600,
    -1803090,
    1910376);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)27U,
    -1667432,
    -1104333,
    -260646,
    -3833893);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)28U,
    -2939036,
    -2235985,
    -420899,
    -2286327);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)29U,
    183443,
    -976891,
    1612842,
    -3545687);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)30U,
    -554416,
    3919660,
    -48306,
    -1362209);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_విడత(re,
    (కొలత_t)31U,
    3937738,
    1400424,
    -846154,
    1976782);
}

స్థిర KRML_MUSTINLINE శూన్య libcrux_ml_dsa_simd_portable_ntt_ntt(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_7(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_6(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_5(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_4(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_3(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0(re);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య libcrux_ml_dsa_simd_portable_ntt_65(Eurydice_arr_a3 *simd_units)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt(simd_units);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta,
  కొలత_t index,
  కొలత_t అడుగు
)
{
  int32_t a_minus_b = simd_unit->దత్తాంశం[index + అడుగు] - simd_unit->దత్తాంశం[index];
  simd_unit->దత్తాంశం[index] += simd_unit->దత్తాంశం[index + అడుగు];
  simd_unit->దత్తాంశం[index + అడుగు] =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      zeta);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta0,
    (కొలత_t)0U,
    (కొలత_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta1,
    (కొలత_t)2U,
    (కొలత_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta2,
    (కొలత_t)4U,
    (కొలత_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta3,
    (కొలత_t)6U,
    (కొలత_t)1U);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(
  Eurydice_arr_a3 *re,
  కొలత_t index,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(&re->దత్తాంశం[index],
    zeta0,
    zeta1,
    zeta2,
    zeta3);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)0U,
    1976782,
    -846154,
    1400424,
    3937738);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)1U,
    -1362209,
    -48306,
    3919660,
    -554416);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)2U,
    -3545687,
    1612842,
    -976891,
    183443);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)3U,
    -2286327,
    -420899,
    -2235985,
    -2939036);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)4U,
    -3833893,
    -260646,
    -1104333,
    -1667432);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)5U,
    1910376,
    -1803090,
    1723600,
    -426683);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)6U,
    472078,
    1717735,
    -975884,
    2213111);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)7U,
    269760,
    3866901,
    3523897,
    -3038916);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)8U,
    -1799107,
    -3694233,
    1652634,
    810149);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)9U,
    3014001,
    1616392,
    162844,
    -3183426);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)10U,
    -1207385,
    185531,
    3369112,
    1957272);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)11U,
    -164721,
    2454455,
    2432395,
    -2013608);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)12U,
    -3776993,
    594136,
    -3724270,
    -2584293);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)13U,
    -1846953,
    -1671176,
    -2831860,
    -542412);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)14U,
    3406031,
    2235880,
    777191,
    1500165);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)15U,
    -1374803,
    -2546312,
    1917081,
    -1279661);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)16U,
    -1962642,
    3306115,
    1312455,
    -451100);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)17U,
    -1430225,
    -3318210,
    1237275,
    -1333058);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)18U,
    -1050970,
    1903435,
    1869119,
    -2994039);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)19U,
    -3548272,
    2635921,
    1250494,
    -3767016);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)20U,
    1595974,
    2486353,
    1247620,
    4055324);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)21U,
    1265009,
    -2590150,
    2691481,
    2842341);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)22U,
    203044,
    1735879,
    -3342277,
    3437287);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)23U,
    4108315,
    -2437823,
    286988,
    342297);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)24U,
    -3595838,
    -768622,
    -525098,
    -3556995);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)25U,
    3207046,
    2031748,
    -3122442,
    -655327);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)26U,
    -522500,
    -43260,
    -1613174,
    495491);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)27U,
    819034,
    909542,
    1859098,
    900702);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)28U,
    -3193378,
    -1197226,
    -3759364,
    -3520352);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)29U,
    3513181,
    -1235728,
    2434439,
    266997);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)30U,
    -3562462,
    -2446433,
    2244091,
    -3342478);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_విడత(re,
    (కొలత_t)31U,
    3817976,
    2316500,
    3407706,
    2091667);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta0,
    (కొలత_t)0U,
    (కొలత_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta0,
    (కొలత_t)1U,
    (కొలత_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta1,
    (కొలత_t)4U,
    (కొలత_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta1,
    (కొలత_t)5U,
    (కొలత_t)2U);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(
  Eurydice_arr_a3 *re,
  కొలత_t index,
  int32_t zeta_00,
  int32_t zeta_01
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(&re->దత్తాంశం[index],
    zeta_00,
    zeta_01);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)0U,
    3839961,
    -3628969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)1U,
    -3881060,
    -3019102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)2U,
    -1439742,
    -812732);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)3U,
    -1584928,
    1285669);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)4U,
    1341330,
    1315589);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)5U,
    -177440,
    -2409325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)6U,
    -1851402,
    3159746);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)7U,
    -3553272,
    189548);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)8U,
    -1316856,
    759969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)9U,
    -210977,
    2389356);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)10U,
    -3249728,
    1653064);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)11U,
    -8578,
    -3724342);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)12U,
    3958618,
    904516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)13U,
    -1100098,
    44288);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)14U,
    3097992,
    508951);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)15U,
    264944,
    -3343383);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)16U,
    -1430430,
    1852771);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)17U,
    1349076,
    -381987);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)18U,
    -1308169,
    -22981);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)19U,
    -1228525,
    -671102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)20U,
    -2477047,
    -411027);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)21U,
    -3693493,
    -2967645);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)22U,
    2715295,
    2147896);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)23U,
    -983419,
    3412210);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)24U,
    126922,
    -3632928);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)25U,
    -3157330,
    -3190144);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)26U,
    -1000202,
    -4083598);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)27U,
    1939314,
    -1257611);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)28U,
    -1585221,
    2176455);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)29U,
    3475950,
    -1452451);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)30U,
    -3041255,
    -3677745);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_విడత(re,
    (కొలత_t)31U,
    -1528703,
    -3930395);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta,
    (కొలత_t)0U,
    (కొలత_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta,
    (కొలత_t)1U,
    (కొలత_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta,
    (కొలత_t)2U,
    (కొలత_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_అడుగు(simd_unit,
    zeta,
    (కొలత_t)3U,
    (కొలత_t)4U);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(
  Eurydice_arr_a3 *re,
  కొలత_t index,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(&re->దత్తాంశం[index], zeta1);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)0U, -2797779);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)1U, 2071892);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)2U, -2556880);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)3U, 3900724);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)4U, 3881043);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)5U, 954230);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)6U, 531354);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)7U, 811944);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)8U, 3699596);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)9U, -1600420);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)10U, -2140649);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)11U, 3507263);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)12U, -3821735);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)13U, 3505694);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)14U, -1643818);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)15U, -1699267);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)16U, -539299);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)17U, 2348700);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)18U, -300467);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)19U, 3539968);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)20U, -2867647);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)21U, 3574422);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)22U, -3043716);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)23U, -3861115);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)24U, 3915439);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)25U, -2537516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)26U, -3592148);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)27U, -1661693);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)28U, 3530437);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)29U, 3077325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)30U, 95776);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_విడత(re, (కొలత_t)31U, 2706023);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 1
- ZETA= 280005
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_30(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      280005);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 2
- STEP_BY= 1
- ZETA= 4010497
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_25(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)2U; i < (కొలత_t)2U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      4010497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 1
- ZETA= -19422
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_43(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)4U; i < (కొలత_t)4U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      -19422);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 6
- STEP_BY= 1
- ZETA= 1757237
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_f4(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)6U; i < (కొలత_t)6U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      1757237);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 1
- ZETA= -3277672
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_82(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)8U; i < (కొలత_t)8U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      -3277672);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 10
- STEP_BY= 1
- ZETA= -1399561
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1d(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)10U; i < (కొలత_t)10U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      -1399561);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 1
- ZETA= -3859737
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)12U; i < (కొలత_t)12U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      -3859737);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 14
- STEP_BY= 1
- ZETA= -2118186
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d8(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)14U; i < (కొలత_t)14U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      -2118186);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 1
- ZETA= -2108549
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_42(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)16U; i < (కొలత_t)16U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      -2108549);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 18
- STEP_BY= 1
- ZETA= 2619752
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_60(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)18U; i < (కొలత_t)18U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      2619752);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 1
- ZETA= -1119584
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_61(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)20U; i < (కొలత_t)20U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      -1119584);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 22
- STEP_BY= 1
- ZETA= -549488
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_29(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)22U; i < (కొలత_t)22U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      -549488);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 1
- ZETA= 3585928
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)24U; i < (కొలత_t)24U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      3585928);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 26
- STEP_BY= 1
- ZETA= -1079900
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_9d(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)26U; i < (కొలత_t)26U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      -1079900);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 1
- ZETA= 1024112
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_38(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)28U; i < (కొలత_t)28U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      1024112);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 30
- STEP_BY= 1
- ZETA= 2725464
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_5f(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)30U; i < (కొలత_t)30U + (కొలత_t)1U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)1U],
      2725464);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_3(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_30(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_25(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_43(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_f4(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_82(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1d(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d8(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_42(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_60(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_61(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_29(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_9d(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_38(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_5f(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 2
- ZETA= 2680103
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_300(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)2U],
      2680103);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 2
- ZETA= 3111497
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_430(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)4U; i < (కొలత_t)4U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)2U],
      3111497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 2
- ZETA= -2884855
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_820(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)8U; i < (కొలత_t)8U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)2U],
      -2884855);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 2
- ZETA= 3119733
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea0(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)12U; i < (కొలత_t)12U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)2U],
      3119733);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 2
- ZETA= -2091905
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_420(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)16U; i < (కొలత_t)16U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)2U],
      -2091905);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 2
- ZETA= -359251
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_610(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)20U; i < (కొలత_t)20U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)2U],
      -359251);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 2
- ZETA= 2353451
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe0(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)24U; i < (కొలత_t)24U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)2U],
      2353451);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 2
- ZETA= 1826347
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_380(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)28U; i < (కొలత_t)28U + (కొలత_t)2U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)2U],
      1826347);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_4(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_300(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_430(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_820(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea0(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_420(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_610(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe0(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_380(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 4
- ZETA= 466468
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_301(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)4U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)4U],
      466468);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 4
- ZETA= -876248
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_821(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)8U; i < (కొలత_t)8U + (కొలత_t)4U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)4U],
      -876248);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 4
- ZETA= -777960
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_421(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)16U; i < (కొలత_t)16U + (కొలత_t)4U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)4U],
      -777960);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 4
- ZETA= 237124
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe1(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)24U; i < (కొలత_t)24U + (కొలత_t)4U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)4U],
      237124);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_5(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_301(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_821(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_421(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe1(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 8
- ZETA= -518909
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_302(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)8U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)8U],
      -518909);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 8
- ZETA= -2608894
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_422(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)16U; i < (కొలత_t)16U + (కొలత_t)8U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)8U],
      -2608894);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_6(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_302(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_422(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 16
- ZETA= 25847
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_303(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)0U + (కొలత_t)16U; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_4d rej = re->దత్తాంశం[j];
    Eurydice_arr_4d rejs = re->దత్తాంశం[j + (కొలత_t)16U];
    libcrux_ml_dsa_simd_portable_arithmetic_కూడు(&re->దత్తాంశం[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_వ్యవకలనం(&re->దత్తాంశం[j + (కొలత_t)16U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[j +
        (కొలత_t)16U],
      25847);
  }
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_7(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_303(re);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_montgomery(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_3(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_4(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_5(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_6(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_7(re);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->దత్తాంశం[i0], 41978);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_invert_ntt_montgomery_65(Eurydice_arr_a3 *simd_units)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_montgomery(simd_units);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_barrett_reduce_simd_unit_65(Eurydice_arr_4d *simd_unit)
{
  libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(simd_unit);
}

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_కొలత (libcrux_ml_dsa_constants_error_ring_element_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_బిట్లు_చొప్పున_ERROR_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_కొలత (libcrux_ml_dsa_constants_commitment_ring_element_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_బిట్లు_చొప్పున_COMMITMENT_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_లోపల_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_కొలత (libcrux_ml_dsa_constants_gamma1_ring_element_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_బిట్లు_చొప్పున_GAMMA1_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_కీలకం_కొలత (libcrux_ml_dsa_constants_verification_కీలకం_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_కొలత (libcrux_ml_dsa_constants_signature_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_లోపల_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_కొలత, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_బిట్లు_చొప్పున_GAMMA1_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_కొలత (libcrux_ml_dsa_constants_error_ring_element_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_బిట్లు_చొప్పున_ERROR_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_కొలత (libcrux_ml_dsa_constants_commitment_ring_element_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_బిట్లు_చొప్పున_COMMITMENT_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_లోపల_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_కొలత (libcrux_ml_dsa_constants_gamma1_ring_element_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_బిట్లు_చొప్పున_GAMMA1_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_VERIFICATION_కీలకం_కొలత (libcrux_ml_dsa_constants_verification_కీలకం_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNATURE_కొలత (libcrux_ml_dsa_constants_signature_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_లోపల_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_కొలత, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_బిట్లు_చొప్పున_GAMMA1_COEFFICIENT))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_సదిశ_కొలత (libcrux_ml_dsa_constants_commitment_సదిశ_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_బిట్లు_చొప్పున_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $2560size_t
*/
రకనిర్వచనం Eurydice_arr_10 libcrux_ml_dsa_types_MLDSASigning_కీలకం_11;

రకనిర్వచనం Eurydice_arr_10 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_Signing_కీలకం;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $1312size_t
*/
రకనిర్వచనం Eurydice_arr_02 libcrux_ml_dsa_types_MLDSAVerification_కీలకం_1d;

రకనిర్వచనం Eurydice_arr_02 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_Verification_కీలకం;

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_అడ్డువరుస_స్తంభం (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A)

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_అడ్డువరుస_X_స్తంభం (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A)

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNING_కీలకం_కొలత (libcrux_ml_dsa_constants_signing_కీలకం_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_కొలత))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_సదిశ_కొలత (libcrux_ml_dsa_constants_commitment_సదిశ_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_బిట్లు_చొప్పున_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $4032size_t
*/
రకనిర్వచనం Eurydice_arr_24 libcrux_ml_dsa_types_MLDSASigning_కీలకం_8e;

రకనిర్వచనం Eurydice_arr_24 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_Signing_కీలకం;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $1952size_t
*/
రకనిర్వచనం Eurydice_arr_29 libcrux_ml_dsa_types_MLDSAVerification_కీలకం_c8;

రకనిర్వచనం Eurydice_arr_29 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_Verification_కీలకం;

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_అడ్డువరుస_స్తంభం (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A)

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_అడ్డువరుస_X_స్తంభం (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A)

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNING_కీలకం_కొలత (libcrux_ml_dsa_constants_signing_కీలకం_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_కొలత))

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_సదిశ_కొలత (libcrux_ml_dsa_constants_commitment_సదిశ_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_బిట్లు_చొప్పున_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $4896size_t
*/
రకనిర్వచనం Eurydice_arr_e2 libcrux_ml_dsa_types_MLDSASigning_కీలకం_b8;

రకనిర్వచనం Eurydice_arr_e2 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_Signing_కీలకం;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $2592size_t
*/
రకనిర్వచనం Eurydice_arr_43 libcrux_ml_dsa_types_MLDSAVerification_కీలకం_e9;

రకనిర్వచనం Eurydice_arr_43 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_Verification_కీలకం;

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_అడ్డువరుస_స్తంభం (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A)

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_అడ్డువరుస_X_స్తంభం (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A)

#నిర్వచించు LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNING_కీలకం_కొలత (libcrux_ml_dsa_constants_signing_కీలకం_కొలత(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_కొలత))

#నిర్వచించు LIBCRUX_ML_DSA_PRE_HASH_PRE_HASH_OID_LEN ((కొలత_t)11U)

రకనిర్వచనం Eurydice_arr_c9 libcrux_ml_dsa_pre_hash_PreHashOID;

రకనిర్వచనం core_ఫలితం_ఫలితం_a8 libcrux_ml_dsa_pre_hash_Pre_Hash_ఫలితం;

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::SigningError}
*/
స్థిర అంతఃవరుస libcrux_ml_dsa_types_SigningError
libcrux_ml_dsa_pre_hash_from_96(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  తిరిగి libcrux_ml_dsa_types_SigningError_ContextTooLongError;
}

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::VerificationError}
*/
స్థిర అంతఃవరుస libcrux_ml_dsa_types_VerificationError
libcrux_ml_dsa_pre_hash_from_bf(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  తిరిగి libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError;
}

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_3_అడుగు ((కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_3_అడుగు_BY ((కొలత_t)1U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_4_అడుగు ((కొలత_t)16U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_4_అడుగు_BY ((కొలత_t)2U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_5_అడుగు ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_5_అడుగు_BY ((కొలత_t)4U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_6_అడుగు ((కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_6_అడుగు_BY ((కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_7_అడుగు ((కొలత_t)128U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_7_అడుగు_BY ((కొలత_t)16U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_3_అడుగు ((కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_3_అడుగు_BY ((కొలత_t)1U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_4_అడుగు ((కొలత_t)16U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_4_అడుగు_BY ((కొలత_t)2U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_5_అడుగు ((కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_5_అడుగు_BY ((కొలత_t)4U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_6_అడుగు ((కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_6_అడుగు_BY ((కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_7_అడుగు ((కొలత_t)128U)

#నిర్వచించు LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_7_అడుగు_BY ((కొలత_t)16U)

రకనిర్వచనం int32_t libcrux_ml_dsa_simd_portable_సదిశ_type_క్షేత్రం_Element;

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
స్థిర అంతఃవరుస Eurydice_arr_4d
libcrux_ml_dsa_simd_portable_సదిశ_type_clone_a5(స్థిరరాశి Eurydice_arr_4d *self)
{
  తిరిగి self[0U];
}

రకనిర్వచనం int32_t libcrux_ml_dsa_simd_traits_క్షేత్రం_Element_Times_Montgomery_R;

రకనిర్వచనం Eurydice_arr_93 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87Signature;

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_c5
with const generics
- SIZE= 4627
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_93
*libcrux_ml_dsa_types_as_ref_c5_f1(స్థిరరాశి Eurydice_arr_93 *self)
{
  తిరిగి self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_7f
with const generics
- SIZE= 2592
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_43
*libcrux_ml_dsa_types_as_ref_7f_c6(స్థిరరాశి Eurydice_arr_43 *self)
{
  తిరిగి self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_9b
with const generics
- SIZE= 4896
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_e2
*libcrux_ml_dsa_types_as_ref_9b_72(స్థిరరాశి Eurydice_arr_e2 *self)
{
  తిరిగి self;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_7f
with const generics
- SIZE= 2592
*/
స్థిర అంతఃవరుస Eurydice_arr_43 libcrux_ml_dsa_types_new_7f_c6(Eurydice_arr_43 విలువ)
{
  తిరిగి విలువ;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_9b
with const generics
- SIZE= 4896
*/
స్థిర అంతఃవరుస Eurydice_arr_e2 libcrux_ml_dsa_types_new_9b_72(Eurydice_arr_e2 విలువ)
{
  తిరిగి విలువ;
}

రకనిర్వచనం Eurydice_arr_85 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44Signature;

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_c5
with const generics
- SIZE= 2420
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_85
*libcrux_ml_dsa_types_as_ref_c5_37(స్థిరరాశి Eurydice_arr_85 *self)
{
  తిరిగి self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_7f
with const generics
- SIZE= 1312
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_02
*libcrux_ml_dsa_types_as_ref_7f_7d(స్థిరరాశి Eurydice_arr_02 *self)
{
  తిరిగి self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_9b
with const generics
- SIZE= 2560
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_10
*libcrux_ml_dsa_types_as_ref_9b_ab(స్థిరరాశి Eurydice_arr_10 *self)
{
  తిరిగి self;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_7f
with const generics
- SIZE= 1312
*/
స్థిర అంతఃవరుస Eurydice_arr_02 libcrux_ml_dsa_types_new_7f_7d(Eurydice_arr_02 విలువ)
{
  తిరిగి విలువ;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_9b
with const generics
- SIZE= 2560
*/
స్థిర అంతఃవరుస Eurydice_arr_10 libcrux_ml_dsa_types_new_9b_ab(Eurydice_arr_10 విలువ)
{
  తిరిగి విలువ;
}

రకనిర్వచనం Eurydice_arr_0c libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65Signature;

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_c5
with const generics
- SIZE= 3309
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_0c
*libcrux_ml_dsa_types_as_ref_c5_5c(స్థిరరాశి Eurydice_arr_0c *self)
{
  తిరిగి self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_7f
with const generics
- SIZE= 1952
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_29
*libcrux_ml_dsa_types_as_ref_7f_a2(స్థిరరాశి Eurydice_arr_29 *self)
{
  తిరిగి self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_9b
with const generics
- SIZE= 4032
*/
స్థిర అంతఃవరుస స్థిరరాశి
Eurydice_arr_24
*libcrux_ml_dsa_types_as_ref_9b_e5(స్థిరరాశి Eurydice_arr_24 *self)
{
  తిరిగి self;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_7f
with const generics
- SIZE= 1952
*/
స్థిర అంతఃవరుస Eurydice_arr_29 libcrux_ml_dsa_types_new_7f_a2(Eurydice_arr_29 విలువ)
{
  తిరిగి విలువ;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_9b
with const generics
- SIZE= 4032
*/
స్థిర అంతఃవరుస Eurydice_arr_24 libcrux_ml_dsa_types_new_9b_e5(Eurydice_arr_24 విలువ)
{
  తిరిగి విలువ;
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87Signature, libcrux_ml_dsa_types_SigningError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_8b_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  సంఘం {
    Eurydice_arr_93 case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_ఫలితం_ఫలితం_8b;

/**
A monomorphic instance of libcrux_ml_dsa.polynomial.PolynomialRingElement
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients

*/
రకనిర్వచనం Eurydice_arr_a3 libcrux_ml_dsa_polynomial_PolynomialRingElement_e8;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $7size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_bb_s { Eurydice_arr_a3 దత్తాంశం[7U]; } Eurydice_arr_bb;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_bb

*/
రకనిర్వచనం నిర్మాణం core_option_Option_2d_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_bb f0;
}
core_option_Option_2d;

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
రకనిర్వచనం నిర్మాణం Eurydice_dst_ref_shared_44_s
{
  స్థిరరాశి Eurydice_arr_a3 *ptr;
  కొలత_t meta;
}
Eurydice_dst_ref_shared_44;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $56size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_0f_s { Eurydice_arr_a3 దత్తాంశం[56U]; } Eurydice_arr_0f;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 56
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_208(స్థిరరాశి Eurydice_arr_0f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)56U;
  తిరిగి lit;
}

/**
 Init with zero
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.zero_c5
with const generics
- SIZE= 4627
*/
స్థిర అంతఃవరుస Eurydice_arr_93 libcrux_ml_dsa_types_zero_c5_f1(శూన్య)
{
  తిరిగి (KRML_CLITERAL(Eurydice_arr_93){ .దత్తాంశం = { 0U } });
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $8size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_8f_s { Eurydice_arr_a3 దత్తాంశం[8U]; } Eurydice_arr_8f;

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$8size_t]]

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_secrets_mem_అభ్యర్థనలు_ct_declassify_6a(స్థిరరాశి Eurydice_arr_8f *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $15size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_92_s { Eurydice_arr_a3 దత్తాంశం[15U]; } Eurydice_arr_92;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_207(స్థిరరాశి Eurydice_arr_92 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)15U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 7
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_206(స్థిరరాశి Eurydice_arr_bb *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)7U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_subslice_shared_251(స్థిరరాశి Eurydice_arr_92 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం }
    );
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
రకనిర్వచనం నిర్మాణం Eurydice_dst_ref_mut_44_s
{
  Eurydice_arr_a3 *ptr;
  కొలత_t meta;
}
Eurydice_dst_ref_mut_44;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 7
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_208(Eurydice_arr_bb *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)7U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 56
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_207(Eurydice_arr_0f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)56U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_206(Eurydice_arr_92 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)15U;
  తిరిగి lit;
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65Signature, libcrux_ml_dsa_types_SigningError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_8c_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  సంఘం {
    Eurydice_arr_0c case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_ఫలితం_ఫలితం_8c;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $5size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_5d_s { Eurydice_arr_a3 దత్తాంశం[5U]; } Eurydice_arr_5d;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_5d

*/
రకనిర్వచనం నిర్మాణం core_option_Option_1e_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_5d f0;
}
core_option_Option_1e;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $30size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_5a_s { Eurydice_arr_a3 దత్తాంశం[30U]; } Eurydice_arr_5a;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_205(స్థిరరాశి Eurydice_arr_5a *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)30U;
  తిరిగి lit;
}

/**
 Init with zero
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.zero_c5
with const generics
- SIZE= 3309
*/
స్థిర అంతఃవరుస Eurydice_arr_0c libcrux_ml_dsa_types_zero_c5_5c(శూన్య)
{
  తిరిగి (KRML_CLITERAL(Eurydice_arr_0c){ .దత్తాంశం = { 0U } });
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $6size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_dc1_s { Eurydice_arr_a3 దత్తాంశం[6U]; } Eurydice_arr_dc1;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_204(స్థిరరాశి Eurydice_arr_dc1 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)6U;
  తిరిగి lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$6size_t]]

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_secrets_mem_అభ్యర్థనలు_ct_declassify_b2(స్థిరరాశి Eurydice_arr_dc1 *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_205(Eurydice_arr_dc1 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)6U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $11size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_47_s { Eurydice_arr_a3 దత్తాంశం[11U]; } Eurydice_arr_47;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_203(స్థిరరాశి Eurydice_arr_47 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)11U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_202(స్థిరరాశి Eurydice_arr_5d *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)5U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_subslice_shared_250(స్థిరరాశి Eurydice_arr_47 *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_204(Eurydice_arr_5d *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)5U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_203(Eurydice_arr_5a *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)30U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_202(Eurydice_arr_47 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)11U;
  తిరిగి lit;
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.zero_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర అంతఃవరుస Eurydice_arr_a3 libcrux_ml_dsa_polynomial_zero_ff_37(శూన్య)
{
  Eurydice_arr_a3 lit;
  Eurydice_arr_4d repeat_వ్యక్తీకరణ[32U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_simd_portable_zero_65();
  }
  జ్ఞాపకం_నకలు(lit.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)32U * పరిమాణం (Eurydice_arr_4d));
  తిరిగి lit;
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.from_i32_array_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_polynomial_from_i32_array_ff_37(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_a3 *ఫలితం
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_from_coefficient_array_65(Eurydice_ముక్క_subslice_shared_47(array,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_లోపల_SIMD_UNIT,
            .చివర = (i0 + (కొలత_t)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_లోపల_SIMD_UNIT
          }
        )),
      &ఫలితం->దత్తాంశం[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.use_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_arithmetic_use_hint_37(
  int32_t gamma2,
  Eurydice_dst_ref_shared_20 hint,
  Eurydice_dst_ref_mut_44 re_సదిశ
)
{
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < re_సదిశ.meta; i0++)
  {
    కొలత_t i1 = i0;
    Eurydice_arr_a3 tmp = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_గమ్యం_ముక్క_shared_af(&hint.ptr[i1]),
      &tmp);
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
    {
      కొలత_t j = i;
      libcrux_ml_dsa_simd_portable_use_hint_65(gamma2, &re_సదిశ.ptr[i1].దత్తాంశం[j], &tmp.దత్తాంశం[j]);
    }
    re_సదిశ.ptr[i1] = tmp;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt_multiply_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(Eurydice_arr_a3 *lhs, స్థిరరాశి Eurydice_arr_a3 *rhs)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_montgomery_multiply_65(&lhs->దత్తాంశం[i0], &rhs->దత్తాంశం[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.add_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_polynomial_కూడు_ff_37(Eurydice_arr_a3 *self, స్థిరరాశి Eurydice_arr_a3 *rhs)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_కూడు_65(&self->దత్తాంశం[i0], &rhs->దత్తాంశం[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.arithmetic.shift_left_then_reduce
with const generics
- SHIFT_BY= 13
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_simd_portable_arithmetic_జరుపు_ఎడమ_then_reduce_84(Eurydice_arr_4d *simd_unit)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    simd_unit->దత్తాంశం[i0] = (int32_t)((uint32_t)simd_unit->దత్తాంశం[i0] << (uint32_t)13);
  }
  libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(simd_unit);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.shift_left_then_reduce_65
with const generics
- SHIFT_BY= 13
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_simd_portable_జరుపు_ఎడమ_then_reduce_65_84(Eurydice_arr_4d *simd_unit)
{
  libcrux_ml_dsa_simd_portable_arithmetic_జరుపు_ఎడమ_then_reduce_84(simd_unit);
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.shift_left_then_reduce
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- SHIFT_BY= 13
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_arithmetic_జరుపు_ఎడమ_then_reduce_68(Eurydice_arr_a3 *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_జరుపు_ఎడమ_then_reduce_65_84(&re->దత్తాంశం[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య libcrux_ml_dsa_ntt_ntt_37(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_65(re);
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.subtract_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_polynomial_వ్యవకలనం_ff_37(Eurydice_arr_a3 *self, స్థిరరాశి Eurydice_arr_a3 *rhs)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_వ్యవకలనం_65(&self->దత్తాంశం[i0], &rhs->దత్తాంశం[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.barrett_reduce_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(Eurydice_arr_a3 *self)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_barrett_reduce_simd_unit_65(&self->దత్తాంశం[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.invert_ntt_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invert_ntt_montgomery_65(re);
}

/**
 Compute InvertNTT(Â ◦ ẑ - ĉ ◦ NTT(t₁2ᵈ))
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_w_approx
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_మాతృక_compute_w_approx_37(
  కొలత_t అడ్డువరుసలు_లోపల_a,
  కొలత_t columns_లోపల_a,
  Eurydice_dst_ref_shared_44 మాతృక,
  Eurydice_dst_ref_shared_44 signer_response,
  స్థిరరాశి Eurydice_arr_a3 *verifier_challenge_as_ntt,
  Eurydice_dst_ref_mut_44 t1
)
{
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < అడ్డువరుసలు_లోపల_a; i0++)
  {
    కొలత_t i1 = i0;
    Eurydice_arr_a3 inner_ఫలితం = libcrux_ml_dsa_polynomial_zero_ff_37();
    కొరకు (కొలత_t i = (కొలత_t)0U; i < columns_లోపల_a; i++)
    {
      కొలత_t j = i;
      Eurydice_arr_a3 లబ్ధం = మాతృక.ptr[i1 * columns_లోపల_a + j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&లబ్ధం, &signer_response.ptr[j]);
      libcrux_ml_dsa_polynomial_కూడు_ff_37(&inner_ఫలితం, &లబ్ధం);
    }
    libcrux_ml_dsa_arithmetic_జరుపు_ఎడమ_then_reduce_68(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&t1.ptr[i1], verifier_challenge_as_ntt);
    libcrux_ml_dsa_polynomial_వ్యవకలనం_ff_37(&inner_ఫలితం, &t1.ptr[i1]);
    t1.ptr[i1] = inner_ఫలితం;
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&t1.ptr[i1]);
  }
}

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_VerificationError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_41_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  libcrux_ml_dsa_types_VerificationError f0;
}
core_ఫలితం_ఫలితం_41;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_gamma1_deserialize_37(
  కొలత_t gamma1_exponent,
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_a3 *ఫలితం
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (gamma1_exponent + (కొలత_t)1U),
            .చివర = (i0 + (కొలత_t)1U) * (gamma1_exponent + (కొలత_t)1U)
          }
        )),
      &ఫలితం->దత్తాంశం[i0],
      gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signature.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_encoding_signature_deserialize_37(
  కొలత_t columns_లోపల_a,
  కొలత_t అడ్డువరుసలు_లోపల_a,
  కొలత_t commitment_hash_కొలత,
  కొలత_t gamma1_exponent,
  కొలత_t gamma1_ring_element_కొలత,
  కొలత_t max_ones_లోపల_hint,
  కొలత_t signature_కొలత,
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం_commitment_hash,
  Eurydice_dst_ref_mut_44 బహిర్గతం_signer_response,
  Eurydice_dst_ref_mut_20 బహిర్గతం_hint
)
{
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(serialized,
      commitment_hash_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 commitment_hash = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 rest_యొక్క_serialized = uu____0.snd;
  Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం_commitment_hash,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = commitment_hash_కొలత })),
    commitment_hash,
    uint8_t);
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(rest_యొక్క_serialized,
      gamma1_ring_element_కొలత * columns_లోపల_a,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 signer_response_serialized = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 hint_serialized = uu____1.snd;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < columns_లోపల_a; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
      Eurydice_ముక్క_subslice_shared_c8(signer_response_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * gamma1_ring_element_కొలత,
            .చివర = (i0 + (కొలత_t)1U) * gamma1_ring_element_కొలత
          }
        )),
      &బహిర్గతం_signer_response.ptr[i0]);
  }
  కొలత_t మునుపటి_true_hints_చూసిన = (కొలత_t)0U;
  bool malformed_hint = false;
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < అడ్డువరుసలు_లోపల_a; i0++)
  {
    కొలత_t i1 = i0;
    కొలత_t current_true_hints_చూసిన = (కొలత_t)(uint32_t)hint_serialized.ptr[max_ones_లోపల_hint + i1];
    ఒకవేళ (current_true_hints_చూసిన < మునుపటి_true_hints_చూసిన)
    {
      malformed_hint = true;
      ఆపు;
    }
    ఒకవేళ (current_true_hints_చూసిన > max_ones_లోపల_hint)
    {
      malformed_hint = true;
      ఆపు;
    }
    కొరకు (కొలత_t i = మునుపటి_true_hints_చూసిన; i < current_true_hints_చూసిన; i++)
    {
      కొలత_t j = i;
      ఒకవేళ (j > మునుపటి_true_hints_చూసిన)
      {
        ఒకవేళ (hint_serialized.ptr[j] <= hint_serialized.ptr[j - (కొలత_t)1U])
        {
          malformed_hint = true;
          ఆపు;
        }
      }
      libcrux_ml_dsa_encoding_signature_సమితి_hint(బహిర్గతం_hint,
        i1,
        (కొలత_t)(uint32_t)hint_serialized.ptr[j]);
    }
    ఒకవేళ (malformed_hint)
    {
      ఆపు;
    }
    మునుపటి_true_hints_చూసిన = current_true_hints_చూసిన;
  }
  కొరకు (కొలత_t i = మునుపటి_true_hints_చూసిన; i < max_ones_లోపల_hint; i++)
  {
    కొలత_t j = i;
    ఒకవేళ (hint_serialized.ptr[j] != 0U)
    {
      malformed_hint = true;
      ఆపు;
    }
  }
  core_ఫలితం_ఫలితం_41 uu____2;
  ఒకవేళ (malformed_hint)
  {
    uu____2 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_MalformedHintError
        }
      );
  }
  లేకపోతే
  {
    uu____2 = (KRML_CLITERAL(core_ఫలితం_ఫలితం_41){ .ట్యాగ్ = core_ఫలితం_Ok });
  }
  తిరిగి uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_encoding_t1_deserialize_37(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_a3 *ఫలితం
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_t1_deserialize_65(Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_కిటికీ,
            .చివర = (i0 + (కొలత_t)1U) * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_కిటికీ
          }
        )),
      &ఫలితం->దత్తాంశం[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_verification_కీలకం_deserialize_37(
  కొలత_t అడ్డువరుసలు_లోపల_a,
  కొలత_t verification_కీలకం_కొలత,
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_dst_ref_mut_44 t1
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < అడ్డువరుసలు_లోపల_a; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_encoding_t1_deserialize_37(Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T1_S_కొలత,
            .చివర = (i0 + (కొలత_t)1U) * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T1_S_కొలత
          }
        )),
      &t1.ptr[i0]);
  }
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44Signature, libcrux_ml_dsa_types_SigningError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_48_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  సంఘం {
    Eurydice_arr_85 case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_ఫలితం_ఫలితం_48;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $4size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_9d_s { Eurydice_arr_a3 దత్తాంశం[4U]; } Eurydice_arr_9d;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_9d

*/
రకనిర్వచనం నిర్మాణం core_option_Option_d9_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  Eurydice_arr_9d f0;
}
core_option_Option_d9;

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_SigningError

*/
రకనిర్వచనం నిర్మాణం core_ఫలితం_ఫలితం_53_s
{
  core_ఫలితం_ఫలితం_57_ట్యాగులు ట్యాగ్;
  libcrux_ml_dsa_types_SigningError f0;
}
core_ఫలితం_ఫలితం_53;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_gamma1_serialize_37(
  స్థిరరాశి Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ముక్క_u8 serialized,
  కొలత_t gamma1_exponent
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    స్థిరరాశి Eurydice_arr_4d *simd_unit = &re->దత్తాంశం[i0];
    libcrux_ml_dsa_simd_portable_gamma1_serialize_65(simd_unit,
      Eurydice_ముక్క_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (gamma1_exponent + (కొలత_t)1U),
            .చివర = (i0 + (కొలత_t)1U) * (gamma1_exponent + (కొలత_t)1U)
          }
        )),
      gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signature.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_signature_serialize_37(
  Eurydice_borrow_ముక్క_u8 commitment_hash,
  Eurydice_dst_ref_shared_44 signer_response,
  Eurydice_dst_ref_shared_20 hint,
  కొలత_t commitment_hash_కొలత,
  కొలత_t columns_లోపల_a,
  కొలత_t అడ్డువరుసలు_లోపల_a,
  కొలత_t gamma1_exponent,
  కొలత_t gamma1_ring_element_కొలత,
  కొలత_t max_ones_లోపల_hint,
  Eurydice_mut_borrow_ముక్క_u8 signature
)
{
  కొలత_t స్థానభ్రంశం = (కొలత_t)0U;
  Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(signature,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = స్థానభ్రంశం,
          .చివర = స్థానభ్రంశం + commitment_hash_కొలత
        }
      )),
    commitment_hash,
    uint8_t);
  స్థానభ్రంశం += commitment_hash_కొలత;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < columns_లోపల_a; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_encoding_gamma1_serialize_37(&signer_response.ptr[i0],
      Eurydice_ముక్క_subslice_mut_c8(signature,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = స్థానభ్రంశం,
            .చివర = స్థానభ్రంశం + gamma1_ring_element_కొలత
          }
        )),
      gamma1_exponent);
    స్థానభ్రంశం += gamma1_ring_element_కొలత;
  }
  కొలత_t true_hints_చూసిన = (కొలత_t)0U;
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < అడ్డువరుసలు_లోపల_a; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)256U; i++)
    {
      కొలత_t j = i;
      ఒకవేళ (hint.ptr[i1].దత్తాంశం[j] == 1)
      {
        signature.ptr[స్థానభ్రంశం + true_hints_చూసిన] = (uint8_t)j;
        true_hints_చూసిన++;
      }
    }
    signature.ptr[స్థానభ్రంశం + max_ones_లోపల_hint + i1] = (uint8_t)true_hints_చూసిన;
  }
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.to_i32_array_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర అంతఃవరుస Eurydice_arr_6c
libcrux_ml_dsa_polynomial_గమ్యం_i32_array_ff_37(స్థిరరాశి Eurydice_arr_a3 *self)
{
  Eurydice_arr_6c ఫలితం = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_గమ్యం_coefficient_array_65(&self->దత్తాంశం[i0],
      Eurydice_array_గమ్యం_subslice_mut_44(&ఫలితం,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_లోపల_SIMD_UNIT,
            .చివర = (i0 + (కొలత_t)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_లోపల_SIMD_UNIT
          }
        )));
  }
  తిరిగి ఫలితం;
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.make_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE కొలత_t
libcrux_ml_dsa_arithmetic_make_hint_37(
  Eurydice_dst_ref_shared_44 దిగువ,
  Eurydice_dst_ref_shared_44 ఎగువ,
  int32_t gamma2,
  Eurydice_dst_ref_mut_20 hint
)
{
  కొలత_t true_hints = (కొలత_t)0U;
  Eurydice_arr_a3 hint_simd = libcrux_ml_dsa_polynomial_zero_ff_37();
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < దిగువ.meta; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
    {
      కొలత_t j = i;
      కొలత_t
      one_hints_లెక్క =
        libcrux_ml_dsa_simd_portable_compute_hint_65(&దిగువ.ptr[i1].దత్తాంశం[j],
          &ఎగువ.ptr[i1].దత్తాంశం[j],
          gamma2,
          &hint_simd.దత్తాంశం[j]);
      true_hints += one_hints_లెక్క;
    }
    Eurydice_arr_6c uu____0 = libcrux_ml_dsa_polynomial_గమ్యం_i32_array_ff_37(&hint_simd);
    hint.ptr[i1] = uu____0;
  }
  తిరిగి true_hints;
}

/**
 CAUTION: This function must only be called with inputs for
 which it is safe to leak the index of a violating coefficient.

 For all norm checks during ML-DSA signature generation it is
 safe to leak the index of a violating coefficient.
*/
/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.infinity_norm_exceeds_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(
  స్థిరరాశి Eurydice_arr_a3 *self,
  int32_t bound
)
{
  bool ఫలితం = false;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    bool
    coeff_exceeds = libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(&self->దత్తాంశం[i0], bound);
    bool uu____0;
    ఒకవేళ (ఫలితం)
    {
      uu____0 = true;
    }
    లేకపోతే
    {
      uu____0 = coeff_exceeds;
    }
    ఫలితం = uu____0;
  }
  తిరిగి ఫలితం;
}

/**
 CAUTION: This function must only be called with inputs for
 which it is safe to leak the index of a violating coefficient.

 For all norm checks during ML-DSA signature generation it is
 safe to leak the index of a violating coefficient.
*/
/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.vector_infinity_norm_exceeds
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(
  Eurydice_dst_ref_shared_44 సదిశ,
  int32_t bound
)
{
  bool ఫలితం = false;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < సదిశ.meta; i++)
  {
    కొలత_t i0 = i;
    bool uu____0;
    ఒకవేళ (ఫలితం)
    {
      uu____0 = true;
    }
    లేకపోతే
    {
      uu____0 = libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(&సదిశ.ptr[i0], bound);
    }
    ఫలితం = uu____0;
  }
  తిరిగి ఫలితం;
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.subtract_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_మాతృక_వ్యవకలనం_vectors_37(
  కొలత_t dimension,
  Eurydice_dst_ref_mut_44 lhs,
  Eurydice_dst_ref_shared_44 rhs
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < dimension; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_polynomial_వ్యవకలనం_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.add_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_మాతృక_కూడు_vectors_37(
  కొలత_t dimension,
  Eurydice_dst_ref_mut_44 lhs,
  Eurydice_dst_ref_shared_44 rhs
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < dimension; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_polynomial_కూడు_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.vector_times_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(
  Eurydice_dst_ref_mut_44 సదిశ,
  స్థిరరాశి Eurydice_arr_a3 *ring_element
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < సదిశ.meta; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&సదిశ.ptr[i0], ring_element);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&సదిశ.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_commitment_serialize_37(
  స్థిరరాశి Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొలత_t output_బైట్లు_చొప్పున_simd_unit = serialized.meta / ((కొలత_t)8U * (కొలత_t)4U);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    స్థిరరాశి Eurydice_arr_4d *simd_unit = &re->దత్తాంశం[i0];
    libcrux_ml_dsa_simd_portable_commitment_serialize_65(simd_unit,
      Eurydice_ముక్క_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * output_బైట్లు_చొప్పున_simd_unit,
            .చివర = (i0 + (కొలత_t)1U) * output_బైట్లు_చొప్పున_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_commitment_serialize_సదిశ_37(
  కొలత_t ring_element_కొలత,
  Eurydice_dst_ref_shared_44 సదిశ,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొలత_t స్థానభ్రంశం = (కొలత_t)0U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < సదిశ.meta; i++)
  {
    కొలత_t _cloop_j = i;
    స్థిరరాశి Eurydice_arr_a3 *ring_element = &సదిశ.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_commitment_serialize_37(ring_element,
      Eurydice_ముక్క_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = స్థానభ్రంశం,
            .చివర = స్థానభ్రంశం + ring_element_కొలత
          }
        )));
    స్థానభ్రంశం += ring_element_కొలత;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.decompose_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_arithmetic_decompose_సదిశ_37(
  కొలత_t dimension,
  int32_t gamma2,
  Eurydice_dst_ref_shared_44 t,
  Eurydice_dst_ref_mut_44 దిగువ,
  Eurydice_dst_ref_mut_44 ఎగువ
)
{
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < dimension; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
    {
      కొలత_t j = i;
      libcrux_ml_dsa_simd_portable_decompose_65(gamma2,
        &t.ptr[i1].దత్తాంశం[j],
        &దిగువ.ptr[i1].దత్తాంశం[j],
        &ఎగువ.ptr[i1].దత్తాంశం[j]);
    }
  }
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $16size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_2f_s { Eurydice_arr_a3 దత్తాంశం[16U]; } Eurydice_arr_2f;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 16
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_201(స్థిరరాశి Eurydice_arr_2f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)16U;
  తిరిగి lit;
}

/**
 Compute InvertNTT(Â ◦ ŷ)
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_matrix_x_mask
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_మాతృక_compute_మాతృక_x_ముసుగు_37(
  కొలత_t అడ్డువరుసలు_లోపల_a,
  కొలత_t columns_లోపల_a,
  Eurydice_dst_ref_shared_44 మాతృక,
  Eurydice_dst_ref_shared_44 ముసుగు,
  Eurydice_dst_ref_mut_44 ఫలితం
)
{
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < అడ్డువరుసలు_లోపల_a; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < columns_లోపల_a; i++)
    {
      కొలత_t j = i;
      Eurydice_arr_a3 లబ్ధం = ముసుగు.ptr[j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&లబ్ధం, &మాతృక.ptr[i1 * columns_లోపల_a + j]);
      libcrux_ml_dsa_polynomial_కూడు_ff_37(&ఫలితం.ptr[i1], &లబ్ధం);
    }
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&ఫలితం.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&ఫలితం.ptr[i1]);
  }
}

/**
A monomorphic instance of core.option.Option
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext

*/
రకనిర్వచనం నిర్మాణం core_option_Option_84_s
{
  core_option_Option_45_ట్యాగులు ట్యాగ్;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext f0;
}
core_option_Option_84;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_t0_deserialize_37(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_a3 *ఫలితం
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_t0_deserialize_65(Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_బైట్లు_చొప్పున_SIMD_UNIT,
            .చివర = (i0 + (కొలత_t)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_బైట్లు_చొప్పున_SIMD_UNIT
          }
        )),
      &ఫలితం->దత్తాంశం[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_t0_deserialize_గమ్యం_సదిశ_then_ntt_37(
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_dst_ref_mut_44 ring_elements
)
{
  కొరకు
  (కొలత_t
    i = (కొలత_t)0U;
    i < serialized.meta / LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T0_S_కొలత;
    i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T0_S_కొలత,
            .చివర = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T0_S_కొలత +
              LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T0_S_కొలత
          }
        ));
    libcrux_ml_dsa_encoding_t0_deserialize_37(బైట్లు, &ring_elements.ptr[i0]);
    libcrux_ml_dsa_ntt_ntt_37(&ring_elements.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_error_deserialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_arr_a3 *ఫలితం
)
{
  కొలత_t chunk_కొలత = libcrux_ml_dsa_encoding_error_chunk_కొలత(eta);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_simd_portable_error_deserialize_65(eta,
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * chunk_కొలత,
            .చివర = (i0 + (కొలత_t)1U) * chunk_కొలత
          }
        )),
      &ఫలితం->దత్తాంశం[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_error_deserialize_గమ్యం_సదిశ_then_ntt_37(
  libcrux_ml_dsa_constants_Eta eta,
  కొలత_t ring_element_కొలత,
  Eurydice_borrow_ముక్క_u8 serialized,
  Eurydice_dst_ref_mut_44 ring_elements
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < serialized.meta / ring_element_కొలత; i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * ring_element_కొలత,
            .చివర = i0 * ring_element_కొలత + ring_element_కొలత
          }
        ));
    libcrux_ml_dsa_encoding_error_deserialize_37(eta, బైట్లు, &ring_elements.ptr[i0]);
    libcrux_ml_dsa_ntt_ntt_37(&ring_elements.ptr[i0]);
  }
}

/**
 Init with zero
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.zero_c5
with const generics
- SIZE= 2420
*/
స్థిర అంతఃవరుస Eurydice_arr_85 libcrux_ml_dsa_types_zero_c5_37(శూన్య)
{
  తిరిగి (KRML_CLITERAL(Eurydice_arr_85){ .దత్తాంశం = { 0U } });
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_t0_serialize_37(
  స్థిరరాశి Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    స్థిరరాశి Eurydice_arr_4d *simd_unit = &re->దత్తాంశం[i0];
    libcrux_ml_dsa_simd_portable_t0_serialize_65(simd_unit,
      Eurydice_ముక్క_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_బైట్లు_చొప్పున_SIMD_UNIT,
            .చివర = (i0 + (కొలత_t)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_బైట్లు_చొప్పున_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_error_serialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  స్థిరరాశి Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొలత_t output_బైట్లు_చొప్పున_simd_unit = libcrux_ml_dsa_encoding_error_chunk_కొలత(eta);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    స్థిరరాశి Eurydice_arr_4d *simd_unit = &re->దత్తాంశం[i0];
    libcrux_ml_dsa_simd_portable_error_serialize_65(eta,
      simd_unit,
      Eurydice_ముక్క_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * output_బైట్లు_చొప్పున_simd_unit,
            .చివర = (i0 + (కొలత_t)1U) * output_బైట్లు_చొప్పున_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_t1_serialize_37(
  స్థిరరాశి Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
  {
    కొలత_t i0 = i;
    స్థిరరాశి Eurydice_arr_4d *simd_unit = &re->దత్తాంశం[i0];
    libcrux_ml_dsa_simd_portable_t1_serialize_65(simd_unit,
      Eurydice_ముక్క_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_బైట్లు_చొప్పున_SIMD_UNIT,
            .చివర = (i0 + (కొలత_t)1U) *
              LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_బైట్లు_చొప్పున_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_verification_కీలకం_generate_serialized_37(
  Eurydice_borrow_ముక్క_u8 విత్తనం,
  Eurydice_dst_ref_shared_44 t1,
  Eurydice_mut_borrow_ముక్క_u8 verification_కీలకం_serialized
)
{
  Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(verification_కీలకం_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)0U,
          .చివర = LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత
        }
      )),
    విత్తనం,
    uint8_t);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < t1.meta; i++)
  {
    కొలత_t i0 = i;
    స్థిరరాశి Eurydice_arr_a3 *ring_element = &t1.ptr[i0];
    కొలత_t
    స్థానభ్రంశం =
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత +
        i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T1_S_కొలత;
    libcrux_ml_dsa_encoding_t1_serialize_37(ring_element,
      Eurydice_ముక్క_subslice_mut_c8(verification_కీలకం_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = స్థానభ్రంశం,
            .చివర = స్థానభ్రంశం + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T1_S_కొలత
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.power2round_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_arithmetic_power2round_సదిశ_37(
  Eurydice_dst_ref_mut_44 t,
  Eurydice_dst_ref_mut_44 t1
)
{
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < t.meta; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)32U; i++)
    {
      కొలత_t j = i;
      libcrux_ml_dsa_simd_portable_power2round_65(&t.ptr[i1].దత్తాంశం[j], &t1.ptr[i1].దత్తాంశం[j]);
    }
  }
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$4size_t]]

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_secrets_mem_అభ్యర్థనలు_ct_declassify_f5(స్థిరరాశి Eurydice_arr_9d *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_200(స్థిరరాశి Eurydice_arr_8f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)8U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 4
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_ముక్క_shared_20(స్థిరరాశి Eurydice_arr_9d *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4U;
  తిరిగి lit;
}

/**
 Compute InvertNTT(Â ◦ ŝ₁) + s₂
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_as1_plus_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_మాతృక_compute_as1_plus_s2_37(
  కొలత_t అడ్డువరుసలు_లోపల_a,
  కొలత_t columns_లోపల_a,
  Eurydice_dst_ref_mut_44 a_as_ntt,
  Eurydice_dst_ref_shared_44 s1_ntt,
  Eurydice_dst_ref_shared_44 s1_s2,
  Eurydice_dst_ref_mut_44 ఫలితం
)
{
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < అడ్డువరుసలు_లోపల_a; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < columns_లోపల_a; i++)
    {
      కొలత_t j = i;
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&a_as_ntt.ptr[i1 * columns_లోపల_a + j],
        &s1_ntt.ptr[j]);
      libcrux_ml_dsa_polynomial_కూడు_ff_37(&ఫలితం.ptr[i1], &a_as_ntt.ptr[i1 * columns_లోపల_a + j]);
    }
  }
  కొరకు (కొలత_t i = (కొలత_t)0U; i < ఫలితం.meta; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&ఫలితం.ptr[i0]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&ఫలితం.ptr[i0]);
    libcrux_ml_dsa_polynomial_కూడు_ff_37(&ఫలితం.ptr[i0], &s1_s2.ptr[columns_లోపల_a + i0]);
  }
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_shared_44
Eurydice_array_గమ్యం_subslice_shared_25(స్థిరరాశి Eurydice_arr_8f *a, core_ops_range_Range_87 r)
{
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->దత్తాంశం + r.ప్రారంభం, .meta = r.చివర - r.ప్రారంభం }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 4
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_201(Eurydice_arr_9d *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)4U;
  తిరిగి lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 16
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_200(Eurydice_arr_2f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)16U;
  తిరిగి lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_field_modulus
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(
  Eurydice_borrow_ముక్క_u8 randomness,
  కొలత_t *sampled_coefficients,
  Eurydice_arr_d0 *బహిర్గతం
)
{
  bool పూర్తి = false;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < randomness.meta / (కొలత_t)24U; i++)
  {
    కొలత_t _cloop_i = i;
    Eurydice_borrow_ముక్క_u8
    random_బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = _cloop_i * (కొలత_t)24U,
            .చివర = _cloop_i * (కొలత_t)24U + (కొలత_t)24U
          }
        ));
    ఒకవేళ (!పూర్తి)
    {
      కొలత_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_క్షేత్రం_modulus_65(random_బైట్లు,
          Eurydice_array_గమ్యం_subslice_from_mut_11(బహిర్గతం, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      ఒకవేళ (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT)
      {
        పూర్తి = true;
      }
    }
  }
  తిరిగి పూర్తి;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
స్థిర అంతఃవరుస Eurydice_dst_ref_mut_44 Eurydice_array_గమ్యం_ముక్క_mut_20(Eurydice_arr_8f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->దత్తాంశం;
  lit.meta = (కొలత_t)8U;
  తిరిగి lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_4
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(
  Eurydice_borrow_ముక్క_u8 randomness,
  కొలత_t *sampled_coefficients,
  Eurydice_arr_d0 *బహిర్గతం
)
{
  bool పూర్తి = false;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < randomness.meta / (కొలత_t)4U; i++)
  {
    కొలత_t _cloop_i = i;
    Eurydice_borrow_ముక్క_u8
    random_బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = _cloop_i * (కొలత_t)4U,
            .చివర = _cloop_i * (కొలత_t)4U + (కొలత_t)4U
          }
        ));
    ఒకవేళ (!పూర్తి)
    {
      కొలత_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(random_బైట్లు,
          Eurydice_array_గమ్యం_subslice_from_mut_11(బహిర్గతం, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      ఒకవేళ (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT)
      {
        పూర్తి = true;
      }
    }
  }
  తిరిగి పూర్తి;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(
  Eurydice_borrow_ముక్క_u8 randomness,
  కొలత_t *sampled_coefficients,
  Eurydice_arr_d0 *బహిర్గతం
)
{
  bool పూర్తి = false;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < randomness.meta / (కొలత_t)4U; i++)
  {
    కొలత_t _cloop_i = i;
    Eurydice_borrow_ముక్క_u8
    random_బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = _cloop_i * (కొలత_t)4U,
            .చివర = _cloop_i * (కొలత_t)4U + (కొలత_t)4U
          }
        ));
    ఒకవేళ (!పూర్తి)
    {
      కొలత_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(random_బైట్లు,
          Eurydice_array_గమ్యం_subslice_from_mut_11(బహిర్గతం, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      ఒకవేళ (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT)
      {
        పూర్తి = true;
      }
    }
  }
  తిరిగి పూర్తి;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ముక్క_u8 randomness,
  కొలత_t *sampled,
  Eurydice_arr_d0 *బహిర్గతం
)
{
  ఎంపిక (eta)
  {
    స్థితి libcrux_ml_dsa_constants_Eta_Two:
      {
        ఆపు;
      }
    స్థితి libcrux_ml_dsa_constants_Eta_Four:
      {
        తిరిగి
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(randomness,
            sampled,
            బహిర్గతం);
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  తిరిగి
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(randomness,
      sampled,
      బహిర్గతం);
}

రకనిర్వచనం నిర్మాణం libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_కీలకం_Pair_s
{
  Eurydice_arr_e2 signing_కీలకం;
  Eurydice_arr_43 verification_కీలకం;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_కీలకం_Pair;

రకనిర్వచనం నిర్మాణం libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_కీలకం_Pair_s
{
  Eurydice_arr_24 signing_కీలకం;
  Eurydice_arr_29 verification_కీలకం;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_కీలకం_Pair;

రకనిర్వచనం నిర్మాణం libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_కీలకం_Pair_s
{
  Eurydice_arr_10 signing_కీలకం;
  Eurydice_arr_02 verification_కీలకం;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_కీలకం_Pair;

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు libcrux_mldsa_core_H_DEFINED
#అయితే_ముగింపు /* libcrux_mldsa_core_H */

/* from libcrux/combined_extraction/generated/libcrux_ct_ops.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే libcrux_ct_ops_H
#నిర్వచించు libcrux_ct_ops_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


/**
 Return 1 if `value` is not zero and 0 otherwise.
*/
స్థిర KRML_NOINLINE uint8_t libcrux_ml_kem_constant_సమయం_ops_inz(uint8_t విలువ)
{
  uint16_t value0 = (uint16_t)(uint32_t)విలువ;
  uint8_t ఫలితం = (uint8_t)((uint32_t)core_అంకె_u16_wrapping_కూడు(~value0, 1U) >> 8U & 0xFFFFU);
  తిరిగి (uint32_t)ఫలితం & 1U;
}

స్థిర KRML_NOINLINE uint8_t libcrux_ml_kem_constant_సమయం_ops_is_non_zero(uint8_t విలువ)
{
  తిరిగి libcrux_ml_kem_constant_సమయం_ops_inz(విలువ);
}

/**
 Return 1 if the bytes of `lhs` and `rhs` do not exactly
 match and 0 otherwise.
*/
స్థిర KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_సమయం_ops_compare(
  Eurydice_borrow_ముక్క_u8 lhs,
  Eurydice_borrow_ముక్క_u8 rhs
)
{
  uint8_t r = 0U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < lhs.meta; i++)
  {
    కొలత_t i0 = i;
    uint8_t nr = (uint32_t)r | ((uint32_t)lhs.ptr[i0] ^ (uint32_t)rhs.ptr[i0]);
    r = nr;
  }
  తిరిగి libcrux_ml_kem_constant_సమయం_ops_is_non_zero(r);
}

స్థిర KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_సమయం_ops_compare_ciphertexts_లోపల_constant_సమయం(
  Eurydice_borrow_ముక్క_u8 lhs,
  Eurydice_borrow_ముక్క_u8 rhs
)
{
  తిరిగి libcrux_ml_kem_constant_సమయం_ops_compare(lhs, rhs);
}

/**
 If `selector` is not zero, return the bytes in `rhs`; return the bytes in
 `lhs` otherwise.
*/
స్థిర KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_సమయం_ops_select_ct(
  Eurydice_borrow_ముక్క_u8 lhs,
  Eurydice_borrow_ముక్క_u8 rhs,
  uint8_t selector
)
{
  uint8_t
  ముసుగు = core_అంకె_u8_wrapping_sub(libcrux_ml_kem_constant_సమయం_ops_is_non_zero(selector), 1U);
  Eurydice_arr_ec బహిర్గతం = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత; i++)
  {
    కొలత_t i0 = i;
    uint8_t
    outi =
      ((uint32_t)lhs.ptr[i0] & (uint32_t)ముసుగు) | ((uint32_t)rhs.ptr[i0] & (~(uint32_t)ముసుగు & 0xFFU));
    బహిర్గతం.దత్తాంశం[i0] = outi;
  }
  తిరిగి బహిర్గతం;
}

స్థిర KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_సమయం_ops_select_shared_secret_లోపల_constant_సమయం(
  Eurydice_borrow_ముక్క_u8 lhs,
  Eurydice_borrow_ముక్క_u8 rhs,
  uint8_t selector
)
{
  తిరిగి libcrux_ml_kem_constant_సమయం_ops_select_ct(lhs, rhs, selector);
}

స్థిర KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_సమయం_ops_compare_ciphertexts_select_shared_secret_లోపల_constant_సమయం(
  Eurydice_borrow_ముక్క_u8 lhs_c,
  Eurydice_borrow_ముక్క_u8 rhs_c,
  Eurydice_borrow_ముక్క_u8 lhs_s,
  Eurydice_borrow_ముక్క_u8 rhs_s
)
{
  uint8_t
  selector = libcrux_ml_kem_constant_సమయం_ops_compare_ciphertexts_లోపల_constant_సమయం(lhs_c, rhs_c);
  తిరిగి
    libcrux_ml_kem_constant_సమయం_ops_select_shared_secret_లోపల_constant_సమయం(lhs_s,
      rhs_s,
      selector);
}

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు libcrux_ct_ops_H_DEFINED
#అయితే_ముగింపు /* libcrux_ct_ops_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే libcrux_mldsa_portable_H
#నిర్వచించు libcrux_mldsa_portable_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


రకనిర్వచనం నిర్మాణం libcrux_ml_dsa_hash_functions_portable_Shake128X4_s
{
  Eurydice_arr_7c state0;
  Eurydice_arr_7c state1;
  Eurydice_arr_7c state2;
  Eurydice_arr_7c state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake128X4;

రకనిర్వచనం libcrux_sha3_portable_KeccakState libcrux_ml_dsa_hash_functions_portable_Shake256;

రకనిర్వచనం నిర్మాణం libcrux_ml_dsa_hash_functions_portable_Shake256X4_s
{
  Eurydice_arr_7c state0;
  Eurydice_arr_7c state1;
  Eurydice_arr_7c state2;
  Eurydice_arr_7c state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake256X4;

రకనిర్వచనం libcrux_sha3_portable_incremental_Shake256Xof
libcrux_ml_dsa_hash_functions_portable_Shake256Xof;

స్థిర KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb(
  Eurydice_borrow_ముక్క_u8 input0,
  Eurydice_borrow_ముక్క_u8 input1,
  Eurydice_borrow_ముక్క_u8 input2,
  Eurydice_borrow_ముక్క_u8 input3
)
{
  Eurydice_arr_7c state0 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state0, input0);
  Eurydice_arr_7c state1 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state1, input1);
  Eurydice_arr_7c state2 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state2, input2);
  Eurydice_arr_7c state3 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state3, input3);
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_dsa_hash_functions_portable_Shake128X4){
        .state0 = state0,
        .state1 = state1,
        .state2 = state2,
        .state3 = state3
      }
    );
}

స్థిర KRML_MUSTINLINE Eurydice_arr_7c
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(
  Eurydice_borrow_ముక్క_u8 ఆదానం
)
{
  Eurydice_arr_7c state = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state, ఆదానం);
  తిరిగి state;
}

స్థిర KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(
  Eurydice_borrow_ముక్క_u8 input0,
  Eurydice_borrow_ముక్క_u8 input1,
  Eurydice_borrow_ముక్క_u8 input2,
  Eurydice_borrow_ముక్క_u8 input3
)
{
  Eurydice_arr_7c state0 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state0, input0);
  Eurydice_arr_7c state1 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state1, input1);
  Eurydice_arr_7c state2 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state2, input2);
  Eurydice_arr_7c state3 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state3, input3);
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_dsa_hash_functions_portable_Shake256X4){
        .state0 = state0,
        .state1 = state1,
        .state2 = state2,
        .state3 = state3
      }
    );
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake128(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_sha3_portable_shake128(బహిర్గతం, ఆదానం);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_ఖండం_shake256(Eurydice_arr_7c *state)
{
  Eurydice_arr_ff బహిర్గతం = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_మొదటి_ఖండం(state,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&బహిర్గతం));
  తిరిగి బహిర్గతం;
}

స్థిర KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_ఖండం_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_ff out0 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_మొదటి_ఖండం(&state->state0,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&out0));
  Eurydice_arr_ff out1 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_మొదటి_ఖండం(&state->state1,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&out1));
  Eurydice_arr_ff out2 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_మొదటి_ఖండం(&state->state2,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&out2));
  Eurydice_arr_ff out3 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_మొదటి_ఖండం(&state->state3,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&out3));
  తిరిగి
    (KRML_CLITERAL(Eurydice_arr_ff_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_five_ఖండాలు(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state,
  Eurydice_arr_d10 *out0,
  Eurydice_arr_d10 *out1,
  Eurydice_arr_d10 *out2,
  Eurydice_arr_d10 *out3
)
{
  libcrux_sha3_portable_incremental_shake128_squeeze_మొదటి_five_ఖండాలు(&state->state0,
    Eurydice_array_గమ్యం_ముక్క_mut_4c(out0));
  libcrux_sha3_portable_incremental_shake128_squeeze_మొదటి_five_ఖండాలు(&state->state1,
    Eurydice_array_గమ్యం_ముక్క_mut_4c(out1));
  libcrux_sha3_portable_incremental_shake128_squeeze_మొదటి_five_ఖండాలు(&state->state2,
    Eurydice_array_గమ్యం_ముక్క_mut_4c(out2));
  libcrux_sha3_portable_incremental_shake128_squeeze_మొదటి_five_ఖండాలు(&state->state3,
    Eurydice_array_గమ్యం_ముక్క_mut_4c(out3));
}

స్థిర KRML_MUSTINLINE Eurydice_arr_c5_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state
)
{
  Eurydice_arr_c5 out0 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_తదుపరి_ఖండం(&state->state0,
    Eurydice_array_గమ్యం_ముక్క_mut_2c(&out0));
  Eurydice_arr_c5 out1 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_తదుపరి_ఖండం(&state->state1,
    Eurydice_array_గమ్యం_ముక్క_mut_2c(&out1));
  Eurydice_arr_c5 out2 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_తదుపరి_ఖండం(&state->state2,
    Eurydice_array_గమ్యం_ముక్క_mut_2c(&out2));
  Eurydice_arr_c5 out3 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_తదుపరి_ఖండం(&state->state3,
    Eurydice_array_గమ్యం_ముక్క_mut_2c(&out3));
  తిరిగి
    (KRML_CLITERAL(Eurydice_arr_c5_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

స్థిర KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_shake256(Eurydice_arr_7c *state)
{
  Eurydice_arr_ff బహిర్గతం = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_తదుపరి_ఖండం(state,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&బహిర్గతం));
  తిరిగి బహిర్గతం;
}

స్థిర KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_ff out0 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_తదుపరి_ఖండం(&state->state0,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&out0));
  Eurydice_arr_ff out1 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_తదుపరి_ఖండం(&state->state1,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&out1));
  Eurydice_arr_ff out2 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_తదుపరి_ఖండం(&state->state2,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&out2));
  Eurydice_arr_ff out3 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_తదుపరి_ఖండం(&state->state3,
    Eurydice_array_గమ్యం_ముక్క_mut_58(&out3));
  తిరిగి
    (KRML_CLITERAL(Eurydice_arr_ff_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::Xof for libcrux_ml_dsa::hash_functions::portable::Shake128}
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake128_7b(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128(ఆదానం, బహిర్గతం);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
స్థిర KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_11(
  Eurydice_borrow_ముక్క_u8 input0,
  Eurydice_borrow_ముక్క_u8 input1,
  Eurydice_borrow_ముక్క_u8 input2,
  Eurydice_borrow_ముక్క_u8 input3
)
{
  తిరిగి libcrux_ml_dsa_hash_functions_portable_init_absorb(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_five_ఖండాలు_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self,
  Eurydice_arr_d10 *out0,
  Eurydice_arr_d10 *out1,
  Eurydice_arr_d10 *out2,
  Eurydice_arr_d10 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_five_ఖండాలు(self, out0, out1, out2, out3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_c5_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self
)
{
  తిరిగి libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_7c
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(Eurydice_borrow_ముక్క_u8 ఆదానం)
{
  తిరిగి libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(ఆదానం);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_ఖండం_61(Eurydice_arr_7c *self)
{
  తిరిగి libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_ఖండం_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_61(Eurydice_arr_7c *self)
{
  తిరిగి libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_hash_functions_portable_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ముక్క_u8 ఆదానం
)
{
  libcrux_sha3_portable_incremental_absorb_42(self, ఆదానం);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_hash_functions_portable_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ముక్క_u8 ఆదానం
)
{
  libcrux_sha3_portable_incremental_absorb_final_42(self, ఆదానం);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
స్థిర అంతఃవరుస libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_ml_dsa_hash_functions_portable_init_26(శూన్య)
{
  తిరిగి libcrux_sha3_portable_incremental_new_42();
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_hash_functions_portable_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_sha3_portable_incremental_squeeze_42(self, బహిర్గతం);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
స్థిర KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(
  Eurydice_borrow_ముక్క_u8 input0,
  Eurydice_borrow_ముక్క_u8 input1,
  Eurydice_borrow_ముక్క_u8 input2,
  Eurydice_borrow_ముక్క_u8 input3
)
{
  తిరిగి libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_ఖండం_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  తిరిగి libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_ఖండం_x4(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  తిరిగి libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_x4(self);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_four_error_ring_elements
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ముక్క_u8 విత్తనం,
  uint16_t ప్రారంభం_సూచీ,
  Eurydice_dst_ref_mut_44 re
)
{
  Eurydice_arr_91 seed0 = libcrux_ml_dsa_sample_కూడు_error_domain_separator(విత్తనం, ప్రారంభం_సూచీ);
  Eurydice_arr_91
  seed1 = libcrux_ml_dsa_sample_కూడు_error_domain_separator(విత్తనం, (uint32_t)ప్రారంభం_సూచీ + 1U);
  Eurydice_arr_91
  seed2 = libcrux_ml_dsa_sample_కూడు_error_domain_separator(విత్తనం, (uint32_t)ప్రారంభం_సూచీ + 2U);
  Eurydice_arr_91
  seed3 = libcrux_ml_dsa_sample_కూడు_error_domain_separator(విత్తనం, (uint32_t)ప్రారంభం_సూచీ + 3U);
  libcrux_ml_dsa_hash_functions_portable_Shake256X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed0),
      Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed1),
      Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed2),
      Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed3));
  Eurydice_arr_ff_x4
  randomnesses0 = libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_ఖండం_x4_9b(&state);
  Eurydice_arr_930
  బహిర్గతం =
    { .దత్తాంశం = { { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } } } };
  కొలత_t sampled0 = (కొలత_t)0U;
  కొలత_t sampled1 = (కొలత_t)0U;
  కొలత_t sampled2 = (కొలత_t)0U;
  కొలత_t sampled3 = (కొలత_t)0U;
  libcrux_ml_dsa_constants_Eta uu____0 = eta;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____0,
      Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses0.fst),
      &sampled0,
      బహిర్గతం.దత్తాంశం);
  libcrux_ml_dsa_constants_Eta uu____1 = eta;
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____1,
      Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses0.snd),
      &sampled1,
      &బహిర్గతం.దత్తాంశం[1U]);
  libcrux_ml_dsa_constants_Eta uu____2 = eta;
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____2,
      Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses0.thd),
      &sampled2,
      &బహిర్గతం.దత్తాంశం[2U]);
  libcrux_ml_dsa_constants_Eta uu____3 = eta;
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____3,
      Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses0.f3),
      &sampled3,
      &బహిర్గతం.దత్తాంశం[3U]);
  అయితే (true)
  {
    ఒకవేళ (done0)
    {
      ఒకవేళ (done1)
      {
        ఒకవేళ (done2)
        {
          ఒకవేళ (done3)
          {
            ఆపు;
          }
          లేకపోతే
          {
            Eurydice_arr_ff_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_x4_9b(&state);
            ఒకవేళ (!done0)
            {
              libcrux_ml_dsa_constants_Eta uu____4 = eta;
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____4,
                  Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.fst),
                  &sampled0,
                  బహిర్గతం.దత్తాంశం);
            }
            ఒకవేళ (!done1)
            {
              libcrux_ml_dsa_constants_Eta uu____5 = eta;
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____5,
                  Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.snd),
                  &sampled1,
                  &బహిర్గతం.దత్తాంశం[1U]);
            }
            ఒకవేళ (!done2)
            {
              libcrux_ml_dsa_constants_Eta uu____6 = eta;
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____6,
                  Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.thd),
                  &sampled2,
                  &బహిర్గతం.దత్తాంశం[2U]);
            }
            ఒకవేళ (!done3)
            {
              libcrux_ml_dsa_constants_Eta uu____7 = eta;
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____7,
                  Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.f3),
                  &sampled3,
                  &బహిర్గతం.దత్తాంశం[3U]);
            }
          }
        }
        లేకపోతే
        {
          Eurydice_arr_ff_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_x4_9b(&state);
          ఒకవేళ (!done0)
          {
            libcrux_ml_dsa_constants_Eta uu____8 = eta;
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____8,
                Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.fst),
                &sampled0,
                బహిర్గతం.దత్తాంశం);
          }
          ఒకవేళ (!done1)
          {
            libcrux_ml_dsa_constants_Eta uu____9 = eta;
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____9,
                Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.snd),
                &sampled1,
                &బహిర్గతం.దత్తాంశం[1U]);
          }
          ఒకవేళ (!done2)
          {
            libcrux_ml_dsa_constants_Eta uu____10 = eta;
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____10,
                Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.thd),
                &sampled2,
                &బహిర్గతం.దత్తాంశం[2U]);
          }
          ఒకవేళ (!done3)
          {
            libcrux_ml_dsa_constants_Eta uu____11 = eta;
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____11,
                Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.f3),
                &sampled3,
                &బహిర్గతం.దత్తాంశం[3U]);
          }
        }
      }
      లేకపోతే
      {
        Eurydice_arr_ff_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_x4_9b(&state);
        ఒకవేళ (!done0)
        {
          libcrux_ml_dsa_constants_Eta uu____12 = eta;
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____12,
              Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.fst),
              &sampled0,
              బహిర్గతం.దత్తాంశం);
        }
        ఒకవేళ (!done1)
        {
          libcrux_ml_dsa_constants_Eta uu____13 = eta;
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____13,
              Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.snd),
              &sampled1,
              &బహిర్గతం.దత్తాంశం[1U]);
        }
        ఒకవేళ (!done2)
        {
          libcrux_ml_dsa_constants_Eta uu____14 = eta;
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____14,
              Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.thd),
              &sampled2,
              &బహిర్గతం.దత్తాంశం[2U]);
        }
        ఒకవేళ (!done3)
        {
          libcrux_ml_dsa_constants_Eta uu____15 = eta;
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____15,
              Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.f3),
              &sampled3,
              &బహిర్గతం.దత్తాంశం[3U]);
        }
      }
    }
    లేకపోతే
    {
      Eurydice_arr_ff_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_x4_9b(&state);
      ఒకవేళ (!done0)
      {
        libcrux_ml_dsa_constants_Eta uu____16 = eta;
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____16,
            Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.fst),
            &sampled0,
            బహిర్గతం.దత్తాంశం);
      }
      ఒకవేళ (!done1)
      {
        libcrux_ml_dsa_constants_Eta uu____17 = eta;
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____17,
            Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.snd),
            &sampled1,
            &బహిర్గతం.దత్తాంశం[1U]);
      }
      ఒకవేళ (!done2)
      {
        libcrux_ml_dsa_constants_Eta uu____18 = eta;
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____18,
            Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.thd),
            &sampled2,
            &బహిర్గతం.దత్తాంశం[2U]);
      }
      ఒకవేళ (!done3)
      {
        libcrux_ml_dsa_constants_Eta uu____19 = eta;
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____19,
            Eurydice_array_గమ్యం_ముక్క_shared_58(&randomnesses.f3),
            &sampled3,
            &బహిర్గతం.దత్తాంశం[3U]);
      }
    }
  }
  కొలత_t max0 = (కొలత_t)(uint32_t)ప్రారంభం_సూచీ + (కొలత_t)4U;
  కొలత_t max;
  ఒకవేళ (re.meta < max0)
  {
    max = re.meta;
  }
  లేకపోతే
  {
    max = max0;
  }
  కొరకు (కొలత_t i = (కొలత_t)(uint32_t)ప్రారంభం_సూచీ; i < max; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_గమ్యం_ముక్క_shared_2c0(&బహిర్గతం.దత్తాంశం[i0
        % (కొలత_t)4U]),
      &re.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.sample_s1_and_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ముక్క_u8 విత్తనం,
  Eurydice_dst_ref_mut_44 s1_s2
)
{
  కొలత_t len = s1_s2.meta;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < len / (కొలత_t)4U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      విత్తనం,
      4U * (uint32_t)(uint16_t)i0,
      s1_s2);
  }
  కొలత_t remainder = len % (కొలత_t)4U;
  ఒకవేళ (remainder != (కొలత_t)0U)
  {
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      విత్తనం,
      (uint16_t)(len - remainder),
      s1_s2);
  }
}

/**
 Sample and write out up to four ring elements.

 If i <= `elements_requested`, a field element with domain separated
 seed according to the provided index is generated in
 `tmp_stack[i]`. After successful rejection sampling in
 `tmp_stack[i]`, the ring element is written to `matrix` at the
 provided index in `indices[i]`.
 `rand_stack` is a working buffer that holds initial Shake output.
*/
/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_up_to_four_ring_elements_flat
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake128X4
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_sample_sample_పైకి_గమ్యం_four_ring_elements_flat_63(
  కొలత_t columns,
  Eurydice_borrow_ముక్క_u8 విత్తనం,
  Eurydice_dst_ref_mut_44 మాతృక,
  Eurydice_arr_d10 *rand_stack0,
  Eurydice_arr_d10 *rand_stack1,
  Eurydice_arr_d10 *rand_stack2,
  Eurydice_arr_d10 *rand_stack3,
  Eurydice_dst_ref_mut_33 tmp_దొంతర,
  కొలత_t ప్రారంభం_సూచీ,
  కొలత_t elements_requested
)
{
  Eurydice_arr_31
  seed0 =
    libcrux_ml_dsa_sample_కూడు_domain_separator(విత్తనం,
      libcrux_ml_dsa_sample_sample_పైకి_గమ్యం_four_ring_elements_flat_xy(ప్రారంభం_సూచీ, columns));
  Eurydice_arr_31
  seed1 =
    libcrux_ml_dsa_sample_కూడు_domain_separator(విత్తనం,
      libcrux_ml_dsa_sample_sample_పైకి_గమ్యం_four_ring_elements_flat_xy(ప్రారంభం_సూచీ + (కొలత_t)1U,
        columns));
  Eurydice_arr_31
  seed2 =
    libcrux_ml_dsa_sample_కూడు_domain_separator(విత్తనం,
      libcrux_ml_dsa_sample_sample_పైకి_గమ్యం_four_ring_elements_flat_xy(ప్రారంభం_సూచీ + (కొలత_t)2U,
        columns));
  Eurydice_arr_31
  seed3 =
    libcrux_ml_dsa_sample_కూడు_domain_separator(విత్తనం,
      libcrux_ml_dsa_sample_sample_పైకి_గమ్యం_four_ring_elements_flat_xy(ప్రారంభం_సూచీ + (కొలత_t)3U,
        columns));
  libcrux_ml_dsa_hash_functions_portable_Shake128X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_11(Eurydice_array_గమ్యం_ముక్క_shared_e9(&seed0),
      Eurydice_array_గమ్యం_ముక్క_shared_e9(&seed1),
      Eurydice_array_గమ్యం_ముక్క_shared_e9(&seed2),
      Eurydice_array_గమ్యం_ముక్క_shared_e9(&seed3));
  libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_five_ఖండాలు_11(&state,
    rand_stack0,
    rand_stack1,
    rand_stack2,
    rand_stack3);
  కొలత_t sampled0 = (కొలత_t)0U;
  కొలత_t sampled1 = (కొలత_t)0U;
  కొలత_t sampled2 = (కొలత_t)0U;
  కొలత_t sampled3 = (కొలత_t)0U;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_4c(rand_stack0),
      &sampled0,
      tmp_దొంతర.ptr);
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_4c(rand_stack1),
      &sampled1,
      &tmp_దొంతర.ptr[1U]);
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_4c(rand_stack2),
      &sampled2,
      &tmp_దొంతర.ptr[2U]);
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_4c(rand_stack3),
      &sampled3,
      &tmp_దొంతర.ptr[3U]);
  అయితే (true)
  {
    ఒకవేళ (done0)
    {
      ఒకవేళ (done1)
      {
        ఒకవేళ (done2)
        {
          ఒకవేళ (done3)
          {
            ఆపు;
          }
          లేకపోతే
          {
            Eurydice_arr_c5_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_11(&state);
            ఒకవేళ (!done0)
            {
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.fst),
                  &sampled0,
                  tmp_దొంతర.ptr);
            }
            ఒకవేళ (!done1)
            {
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.snd),
                  &sampled1,
                  &tmp_దొంతర.ptr[1U]);
            }
            ఒకవేళ (!done2)
            {
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.thd),
                  &sampled2,
                  &tmp_దొంతర.ptr[2U]);
            }
            ఒకవేళ (!done3)
            {
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.f3),
                  &sampled3,
                  &tmp_దొంతర.ptr[3U]);
            }
          }
        }
        లేకపోతే
        {
          Eurydice_arr_c5_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_11(&state);
          ఒకవేళ (!done0)
          {
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.fst),
                &sampled0,
                tmp_దొంతర.ptr);
          }
          ఒకవేళ (!done1)
          {
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.snd),
                &sampled1,
                &tmp_దొంతర.ptr[1U]);
          }
          ఒకవేళ (!done2)
          {
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.thd),
                &sampled2,
                &tmp_దొంతర.ptr[2U]);
          }
          ఒకవేళ (!done3)
          {
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.f3),
                &sampled3,
                &tmp_దొంతర.ptr[3U]);
          }
        }
      }
      లేకపోతే
      {
        Eurydice_arr_c5_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_11(&state);
        ఒకవేళ (!done0)
        {
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.fst),
              &sampled0,
              tmp_దొంతర.ptr);
        }
        ఒకవేళ (!done1)
        {
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.snd),
              &sampled1,
              &tmp_దొంతర.ptr[1U]);
        }
        ఒకవేళ (!done2)
        {
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.thd),
              &sampled2,
              &tmp_దొంతర.ptr[2U]);
        }
        ఒకవేళ (!done3)
        {
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.f3),
              &sampled3,
              &tmp_దొంతర.ptr[3U]);
        }
      }
    }
    లేకపోతే
    {
      Eurydice_arr_c5_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_11(&state);
      ఒకవేళ (!done0)
      {
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.fst),
            &sampled0,
            tmp_దొంతర.ptr);
      }
      ఒకవేళ (!done1)
      {
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.snd),
            &sampled1,
            &tmp_దొంతర.ptr[1U]);
      }
      ఒకవేళ (!done2)
      {
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.thd),
            &sampled2,
            &tmp_దొంతర.ptr[2U]);
      }
      ఒకవేళ (!done3)
      {
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_క్షేత్రం_modulus_37(Eurydice_array_గమ్యం_ముక్క_shared_2c(&randomnesses.f3),
            &sampled3,
            &tmp_దొంతర.ptr[3U]);
      }
    }
  }
  కొరకు (కొలత_t i = (కొలత_t)0U; i < elements_requested; i++)
  {
    కొలత_t k = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_గమ్యం_ముక్క_shared_2c0(&tmp_దొంతర.ptr[k]),
      &మాతృక.ptr[ప్రారంభం_సూచీ + k]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.matrix_flat
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake128X4
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_samplex4_మాతృక_flat_63(
  కొలత_t columns,
  Eurydice_borrow_ముక్క_u8 విత్తనం,
  Eurydice_dst_ref_mut_44 మాతృక
)
{
  Eurydice_arr_d10 rand_stack0 = { .దత్తాంశం = { 0U } };
  Eurydice_arr_d10 rand_stack1 = { .దత్తాంశం = { 0U } };
  Eurydice_arr_d10 rand_stack2 = { .దత్తాంశం = { 0U } };
  Eurydice_arr_d10 rand_stack3 = { .దత్తాంశం = { 0U } };
  Eurydice_arr_930
  tmp_దొంతర =
    { .దత్తాంశం = { { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } } } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < మాతృక.meta / (కొలత_t)4U + (కొలత_t)1U; i++)
  {
    కొలత_t ప్రారంభం_సూచీ = i;
    కొలత_t ప్రారంభం_index0 = ప్రారంభం_సూచీ * (కొలత_t)4U;
    ఒకవేళ (ప్రారంభం_index0 >= మాతృక.meta)
    {
      ఆపు;
    }
    కొలత_t elements_requested;
    ఒకవేళ (ప్రారంభం_index0 + (కొలత_t)4U <= మాతృక.meta)
    {
      elements_requested = (కొలత_t)4U;
    }
    లేకపోతే
    {
      elements_requested = మాతృక.meta - ప్రారంభం_index0;
    }
    libcrux_ml_dsa_sample_sample_పైకి_గమ్యం_four_ring_elements_flat_63(columns,
      విత్తనం,
      మాతృక,
      &rand_stack0,
      &rand_stack1,
      &rand_stack2,
      &rand_stack3,
      Eurydice_array_గమ్యం_ముక్క_mut_7e(&tmp_దొంతర),
      ప్రారంభం_index0,
      elements_requested);
  }
}

/**
This function found in impl {libcrux_ml_dsa::samplex4::X4Sampler for libcrux_ml_dsa::samplex4::portable::PortableSampler}
*/
/**
A monomorphic instance of libcrux_ml_dsa.samplex4.portable.matrix_flat_a8
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(
  కొలత_t columns,
  Eurydice_borrow_ముక్క_u8 విత్తనం,
  Eurydice_dst_ref_mut_44 మాతృక
)
{
  libcrux_ml_dsa_samplex4_మాతృక_flat_63(columns, విత్తనం, మాతృక);
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 64
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake256_c9(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_arr_c7 *బహిర్గతం
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_గమ్యం_ముక్క_mut_17(బహిర్గతం), ఆదానం);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 64
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_arr_c7 *బహిర్గతం
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_c9(ఆదానం, బహిర్గతం);
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signing_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_encoding_signing_కీలకం_generate_serialized_2e(
  libcrux_ml_dsa_constants_Eta eta,
  కొలత_t error_ring_element_కొలత,
  Eurydice_borrow_ముక్క_u8 విత్తనం_మాతృక,
  Eurydice_borrow_ముక్క_u8 విత్తనం_signing,
  Eurydice_borrow_ముక్క_u8 verification_కీలకం,
  Eurydice_dst_ref_shared_44 s1_2,
  Eurydice_dst_ref_shared_44 t0,
  Eurydice_mut_borrow_ముక్క_u8 signing_కీలకం_serialized
)
{
  కొలత_t స్థానభ్రంశం = (కొలత_t)0U;
  Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(signing_కీలకం_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = స్థానభ్రంశం,
          .చివర = స్థానభ్రంశం + LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత
        }
      )),
    విత్తనం_మాతృక,
    uint8_t);
  స్థానభ్రంశం += LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత;
  Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(signing_కీలకం_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = స్థానభ్రంశం,
          .చివర = స్థానభ్రంశం + LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_SIGNING_కొలత
        }
      )),
    విత్తనం_signing,
    uint8_t);
  స్థానభ్రంశం += LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_SIGNING_కొలత;
  Eurydice_arr_c7 verification_కీలకం_hash = { .దత్తాంశం = { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(verification_కీలకం,
    &verification_కీలకం_hash);
  Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(signing_కీలకం_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = స్థానభ్రంశం,
          .చివర = స్థానభ్రంశం + LIBCRUX_ML_DSA_CONSTANTS_బైట్లు_FOR_VERIFICATION_కీలకం_HASH
        }
      )),
    Eurydice_array_గమ్యం_ముక్క_shared_17(&verification_కీలకం_hash),
    uint8_t);
  స్థానభ్రంశం += LIBCRUX_ML_DSA_CONSTANTS_బైట్లు_FOR_VERIFICATION_కీలకం_HASH;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < s1_2.meta; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_encoding_error_serialize_37(eta,
      &s1_2.ptr[i0],
      Eurydice_ముక్క_subslice_mut_c8(signing_కీలకం_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = స్థానభ్రంశం,
            .చివర = స్థానభ్రంశం + error_ring_element_కొలత
          }
        )));
    స్థానభ్రంశం += error_ring_element_కొలత;
  }
  కొరకు (కొలత_t i = (కొలత_t)0U; i < t0.meta; i++)
  {
    కొలత_t _cloop_j = i;
    స్థిరరాశి Eurydice_arr_a3 *ring_element = &t0.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_t0_serialize_37(ring_element,
      Eurydice_ముక్క_subslice_mut_c8(signing_కీలకం_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = స్థానభ్రంశం,
            .చివర = స్థానభ్రంశం + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T0_S_కొలత
          }
        )));
    స్థానభ్రంశం += LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_యొక్క_T0_S_కొలత;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_generate_కీలకం_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_mut_borrow_ముక్క_u8 verification_కీలకం
)
{
  Eurydice_arr_89 విత్తనం_expanded0 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .దత్తాంశం = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_mut_78(&విత్తనం_expanded0));
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_78(&విత్తనం_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 విత్తనం_expanded = uu____0.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(విత్తనం_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_ERROR_VECTORS_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_error_vectors = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_signing = uu____1.snd;
  Eurydice_arr_8f s1_s2;
  Eurydice_arr_a3 repeat_expression0[8U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s1_s2.దత్తాంశం, repeat_expression0, (కొలత_t)8U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    విత్తనం_for_error_vectors,
    Eurydice_array_గమ్యం_ముక్క_mut_20(&s1_s2));
  Eurydice_arr_9d t0;
  Eurydice_arr_a3 repeat_expression1[4U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t0.దత్తాంశం, repeat_expression1, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_2f a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[16U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(a_as_ntt.దత్తాంశం, repeat_expression2, (కొలత_t)16U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
    విత్తనం_for_a,
    Eurydice_array_గమ్యం_ముక్క_mut_200(&a_as_ntt));
  Eurydice_arr_9d s1_ntt;
  Eurydice_arr_a3 repeat_expression3[4U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s1_ntt.దత్తాంశం, repeat_expression3, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_201(&s1_ntt),
    Eurydice_array_గమ్యం_subslice_shared_25(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)0U,
          .చివర = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A
        }
      )),
    Eurydice_arr_a3);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.దత్తాంశం[i0]);
  }
  libcrux_ml_dsa_మాతృక_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
    Eurydice_array_గమ్యం_ముక్క_mut_200(&a_as_ntt),
    Eurydice_array_గమ్యం_ముక్క_shared_20(&s1_ntt),
    Eurydice_array_గమ్యం_ముక్క_shared_200(&s1_s2),
    Eurydice_array_గమ్యం_ముక్క_mut_201(&t0));
  Eurydice_arr_9d t1;
  Eurydice_arr_a3 repeat_వ్యక్తీకరణ[4U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t1.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_సదిశ_37(Eurydice_array_గమ్యం_ముక్క_mut_201(&t0),
    Eurydice_array_గమ్యం_ముక్క_mut_201(&t1));
  libcrux_ml_dsa_encoding_verification_కీలకం_generate_serialized_37(విత్తనం_for_a,
    Eurydice_array_గమ్యం_ముక్క_shared_20(&t1),
    verification_కీలకం);
  libcrux_ml_dsa_encoding_signing_కీలకం_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_కొలత,
    విత్తనం_for_a,
    విత్తనం_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){
        .ptr = verification_కీలకం.ptr,
        .meta = verification_కీలకం.meta
      }
    ),
    Eurydice_array_గమ్యం_ముక్క_shared_200(&s1_s2),
    Eurydice_array_గమ్యం_ముక్క_shared_20(&t0),
    signing_కీలకం);
}

/**
 Generate key pair.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_generate_కీలకం_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_10 *signing_కీలకం,
  Eurydice_arr_02 *verification_కీలకం
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_generate_కీలకం_pair_5a(randomness,
    Eurydice_array_గమ్యం_ముక్క_mut_34(signing_కీలకం),
    Eurydice_array_గమ్యం_ముక్క_mut_9f0(verification_కీలకం));
}

/**
 This corresponds to line 6 in algorithm 7 in FIPS 204 (line 7 in algorithm
 8, resp.).

 If `domain_separation_context` is supplied, applies domain
 separation and length encoding to the context string,
 before appending the message (in the regular variant) or the
 pre-hash OID as well as the pre-hashed message digest. Otherwise,
 it is assumed that `message` already contains domain separation
 information.

 In FIPS 204 M' is the concatenation of the domain separated context, any
 potential pre-hash OID and the message (or the message pre-hash). We do not
 explicitely construct the concatenation in memory since it is of statically unknown
 length, but feed its components directly into the incremental XOF.

 Refer to line 10 of Algorithm 2 (and line 5 of Algorithm 3, resp.) in [FIPS
 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#section.5)
 for details on the domain separation for regular ML-DSA. Line
 23 of Algorithm 4 (and line 18 of Algorithm 5,resp.) describe domain separation for the HashMl-DSA
 variant.
*/
/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.derive_message_representative
with types libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_ml_dsa_generic_derive_సందేశం_representative_43(
  Eurydice_borrow_ముక్క_u8 verification_కీలకం_hash,
  స్థిరరాశి core_option_Option_84 *domain_separation_context,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_arr_c7 *సందేశం_representative
)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake, verification_కీలకం_hash);
  ఒకవేళ (domain_separation_context->ట్యాగ్ == core_option_Some)
  {
    స్థిరరాశి
    libcrux_ml_dsa_pre_hash_DomainSeparationContext
    *domain_separation_context0 = &domain_separation_context->f0;
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *uu____0 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_82
    lvalue0 =
      {
        .దత్తాంశం = {
          (uint8_t)core_option__core__option__Option_T__TraitClause_0___is_some(libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0),
            Eurydice_arr_c9,
            bool)
        }
      };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____0,
      Eurydice_array_గమ్యం_ముక్క_shared_79(&lvalue0));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *uu____1 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_82
    lvalue =
      { .దత్తాంశం = { (uint8_t)libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0).meta } };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____1,
      Eurydice_array_గమ్యం_ముక్క_shared_79(&lvalue));
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0));
    స్థిరరాశి
    core_option_Option_57
    *uu____2 = libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0);
    ఒకవేళ (uu____2->ట్యాగ్ == core_option_Some)
    {
      స్థిరరాశి Eurydice_arr_c9 *pre_hash_oid = &uu____2->f0;
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_shared_2f(pre_hash_oid));
    }
  }
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake, సందేశం_2);
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_mut_17(సందేశం_representative));
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 576
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake256_5a(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_arr_220 *బహిర్గతం
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_గమ్యం_ముక్క_mut_8a(బహిర్గతం), ఆదానం);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 576
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_5a(
  Eurydice_borrow_ముక్క_u8 input0,
  Eurydice_borrow_ముక్క_u8 input1,
  Eurydice_borrow_ముక్క_u8 input2,
  Eurydice_borrow_ముక్క_u8 input3,
  Eurydice_arr_220 *out0,
  Eurydice_arr_220 *out1,
  Eurydice_arr_220 *out2,
  Eurydice_arr_220 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(input0, out0);
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(input1, out1);
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(input2, out2);
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(input3, out3);
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 640
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake256_0e(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_arr_20 *బహిర్గతం
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_గమ్యం_ముక్క_mut_4f(బహిర్గతం), ఆదానం);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 640
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_0e(
  Eurydice_borrow_ముక్క_u8 input0,
  Eurydice_borrow_ముక్క_u8 input1,
  Eurydice_borrow_ముక్క_u8 input2,
  Eurydice_borrow_ముక్క_u8 input3,
  Eurydice_arr_20 *out0,
  Eurydice_arr_20 *out1,
  Eurydice_arr_20 *out2,
  Eurydice_arr_20 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(input0, out0);
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(input1, out1);
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(input2, out2);
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(input3, out3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 640
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake256_61_0e(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_arr_20 *బహిర్గతం
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(ఆదానం, బహిర్గతం);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 576
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_hash_functions_portable_shake256_61_5a(
  Eurydice_borrow_ముక్క_u8 ఆదానం,
  Eurydice_arr_220 *బహిర్గతం
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(ఆదానం, బహిర్గతం);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_sample_sample_ముసుగు_ring_element_2e(
  స్థిరరాశి Eurydice_arr_91 *విత్తనం,
  Eurydice_arr_a3 *ఫలితం,
  కొలత_t gamma1_exponent
)
{
  ఎంపిక (gamma1_exponent)
  {
    స్థితి 17U:
      {
        ఆపు;
      }
    స్థితి 19U:
      {
        Eurydice_arr_20 బహిర్గతం = { .దత్తాంశం = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_61_0e(Eurydice_array_గమ్యం_ముక్క_shared_f1(విత్తనం),
          &బహిర్గతం);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_గమ్యం_ముక్క_shared_4f(&బహిర్గతం),
          ఫలితం);
        తిరిగి;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  Eurydice_arr_220 బహిర్గతం = { .దత్తాంశం = { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_5a(Eurydice_array_గమ్యం_ముక్క_shared_f1(విత్తనం),
    &బహిర్గతం);
  libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
    Eurydice_array_గమ్యం_ముక్క_shared_8a(&బహిర్గతం),
    ఫలితం);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_sample_sample_ముసుగు_సదిశ_67(
  కొలత_t dimension,
  కొలత_t gamma1_exponent,
  స్థిరరాశి Eurydice_arr_c7 *విత్తనం,
  uint16_t *domain_separator,
  Eurydice_dst_ref_mut_44 ముసుగు
)
{
  Eurydice_arr_91
  seed0 =
    libcrux_ml_dsa_sample_కూడు_error_domain_separator(Eurydice_array_గమ్యం_ముక్క_shared_17(విత్తనం),
      domain_separator[0U]);
  Eurydice_arr_91
  seed1 =
    libcrux_ml_dsa_sample_కూడు_error_domain_separator(Eurydice_array_గమ్యం_ముక్క_shared_17(విత్తనం),
      (uint32_t)domain_separator[0U] + 1U);
  Eurydice_arr_91
  seed2 =
    libcrux_ml_dsa_sample_కూడు_error_domain_separator(Eurydice_array_గమ్యం_ముక్క_shared_17(విత్తనం),
      (uint32_t)domain_separator[0U] + 2U);
  Eurydice_arr_91
  seed3 =
    libcrux_ml_dsa_sample_కూడు_error_domain_separator(Eurydice_array_గమ్యం_ముక్క_shared_17(విత్తనం),
      (uint32_t)domain_separator[0U] + 3U);
  domain_separator[0U] = (uint32_t)domain_separator[0U] + 4U;
  ఎంపిక (gamma1_exponent)
  {
    స్థితి 17U:
      {
        Eurydice_arr_220 out0 = { .దత్తాంశం = { 0U } };
        Eurydice_arr_220 out1 = { .దత్తాంశం = { 0U } };
        Eurydice_arr_220 out2 = { .దత్తాంశం = { 0U } };
        Eurydice_arr_220 out3 = { .దత్తాంశం = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_5a(Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed0),
          Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed1),
          Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed2),
          Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_గమ్యం_ముక్క_shared_8a(&out0),
          ముసుగు.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_గమ్యం_ముక్క_shared_8a(&out1),
          &ముసుగు.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_గమ్యం_ముక్క_shared_8a(&out2),
          &ముసుగు.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_గమ్యం_ముక్క_shared_8a(&out3),
          &ముసుగు.ptr[3U]);
        ఆపు;
      }
    స్థితి 19U:
      {
        Eurydice_arr_20 out0 = { .దత్తాంశం = { 0U } };
        Eurydice_arr_20 out1 = { .దత్తాంశం = { 0U } };
        Eurydice_arr_20 out2 = { .దత్తాంశం = { 0U } };
        Eurydice_arr_20 out3 = { .దత్తాంశం = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_0e(Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed0),
          Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed1),
          Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed2),
          Eurydice_array_గమ్యం_ముక్క_shared_f1(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_గమ్యం_ముక్క_shared_4f(&out0),
          ముసుగు.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_గమ్యం_ముక్క_shared_4f(&out1),
          &ముసుగు.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_గమ్యం_ముక్క_shared_4f(&out2),
          &ముసుగు.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_గమ్యం_ముక్క_shared_4f(&out3),
          &ముసుగు.ptr[3U]);
        ఆపు;
      }
    అప్రమేయ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  కొరకు (కొలత_t i = (కొలత_t)4U; i < dimension; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_91
    seed4 =
      libcrux_ml_dsa_sample_కూడు_error_domain_separator(Eurydice_array_గమ్యం_ముక్క_shared_17(విత్తనం),
        domain_separator[0U]);
    domain_separator[0U] = (uint32_t)domain_separator[0U] + 1U;
    libcrux_ml_dsa_sample_sample_ముసుగు_ring_element_2e(&seed4, &ముసుగు.ptr[i0], gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_challenge_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(
  Eurydice_borrow_ముక్క_u8 విత్తనం,
  కొలత_t సంఖ్య_యొక్క_ones,
  Eurydice_arr_a3 *re
)
{
  Eurydice_arr_7c state = libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(విత్తనం);
  Eurydice_arr_ff
  randomness0 = libcrux_ml_dsa_hash_functions_portable_squeeze_మొదటి_ఖండం_61(&state);
  Eurydice_array_u8x8 arr;
  జ్ఞాపకం_నకలు(arr.దత్తాంశం,
    Eurydice_array_గమ్యం_subslice_shared_d40(&randomness0,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)8U })).ptr,
    (కొలత_t)8U * పరిమాణం (uint8_t));
  uint64_t
  signs =
    core_అంకె_u64_from_le_బైట్లు(core_ఫలితం_unwrap_26_e0((
          KRML_CLITERAL(core_ఫలితం_ఫలితం_8e){ .ట్యాగ్ = core_ఫలితం_Ok, .val = { .case_Ok = arr } }
        )));
  Eurydice_arr_6c ఫలితం = { .దత్తాంశం = { 0U } };
  కొలత_t బహిర్గతం_సూచీ = (కొలత_t)256U - సంఖ్య_యొక్క_ones;
  bool
  పూర్తి =
    libcrux_ml_dsa_sample_inside_బహిర్గతం_shuffle(Eurydice_array_గమ్యం_subslice_from_shared_5f(&randomness0,
        (కొలత_t)8U),
      &బహిర్గతం_సూచీ,
      &signs,
      &ఫలితం);
  అయితే (true)
  {
    ఒకవేళ (పూర్తి)
    {
      ఆపు;
    }
    లేకపోతే
    {
      Eurydice_arr_ff
      randomness = libcrux_ml_dsa_hash_functions_portable_squeeze_తదుపరి_ఖండం_61(&state);
      పూర్తి =
        libcrux_ml_dsa_sample_inside_బహిర్గతం_shuffle(Eurydice_array_గమ్యం_ముక్క_shared_58(&randomness),
          &బహిర్గతం_సూచీ,
          &signs,
          &ఫలితం);
    }
  }
  libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_గమ్యం_ముక్క_shared_af(&ఫలితం), re);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_అంతర్గత_5a(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(signing_కీలకం,
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized0 = uu____0.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_SIGNING_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_signing = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized1 = uu____1.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____2 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_బైట్లు_FOR_VERIFICATION_కీలకం_HASH,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 verification_కీలకం_hash = uu____2.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized2 = uu____2.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____3 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_కొలత *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized = uu____3.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____4 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_కొలత *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_ముక్క_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_9d s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[4U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s1_as_ntt.దత్తాంశం, repeat_expression0, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_9d s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[4U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s2_as_ntt.దత్తాంశం, repeat_expression1, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_9d t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[4U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t0_as_ntt.దత్తాంశం, repeat_expression2, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_గమ్యం_సదిశ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_కొలత,
    s1_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_201(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_గమ్యం_సదిశ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_కొలత,
    s2_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_201(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_గమ్యం_సదిశ_then_ntt_37(t0_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_201(&t0_as_ntt));
  Eurydice_arr_2f మాతృక;
  Eurydice_arr_a3 repeat_expression3[16U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(మాతృక.దత్తాంశం, repeat_expression3, (కొలత_t)16U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
    విత్తనం_for_a,
    Eurydice_array_గమ్యం_ముక్క_mut_200(&మాతృక));
  Eurydice_arr_c7 సందేశం_representative = { .దత్తాంశం = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_సందేశం_representative_43(verification_కీలకం_hash,
    &domain_separation_context,
    సందేశం_2,
    &సందేశం_representative);
  Eurydice_arr_c7 ముసుగు_విత్తనం = { .దత్తాంశం = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, విత్తనం_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_గమ్యం_ముక్క_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_గమ్యం_ముక్క_shared_17(&సందేశం_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_గమ్యం_ముక్క_mut_17(&ముసుగు_విత్తనం));
  uint16_t domain_separator_for_ముసుగు = 0U;
  కొలత_t attempt = (కొలత_t)0U;
  core_option_Option_14 commitment_hash0 = { .ట్యాగ్ = core_option_None };
  core_option_Option_d9 signer_response0 = { .ట్యాగ్ = core_option_None };
  core_option_Option_51 hint0 = { .ట్యాగ్ = core_option_None };
  అయితే (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_9d ముసుగు;
    Eurydice_arr_a3 repeat_expression4[4U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(ముసుగు.దత్తాంశం, repeat_expression4, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
    Eurydice_arr_9d w0;
    Eurydice_arr_a3 repeat_expression5[4U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(w0.దత్తాంశం, repeat_expression5, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
    Eurydice_arr_9d commitment;
    Eurydice_arr_a3 repeat_expression6[4U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(commitment.దత్తాంశం, repeat_expression6, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_ముసుగు_సదిశ_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
      &ముసుగు_విత్తనం,
      &domain_separator_for_ముసుగు,
      Eurydice_array_గమ్యం_ముక్క_mut_201(&ముసుగు));
    Eurydice_arr_9d a_x_ముసుగు;
    Eurydice_arr_a3 repeat_వ్యక్తీకరణ[4U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
    {
      repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(a_x_ముసుగు.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
    Eurydice_arr_9d
    ముసుగు_ntt =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)4U,
        &ముసుగు,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
    {
      కొలత_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&ముసుగు_ntt.దత్తాంశం[i0]);
    }
    libcrux_ml_dsa_మాతృక_compute_మాతృక_x_ముసుగు_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
      Eurydice_array_గమ్యం_ముక్క_shared_201(&మాతృక),
      Eurydice_array_గమ్యం_ముక్క_shared_20(&ముసుగు_ntt),
      Eurydice_array_గమ్యం_ముక్క_mut_201(&a_x_ముసుగు));
    libcrux_ml_dsa_arithmetic_decompose_సదిశ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
      Eurydice_array_గమ్యం_ముక్క_shared_20(&a_x_ముసుగు),
      Eurydice_array_గమ్యం_ముక్క_mut_201(&w0),
      Eurydice_array_గమ్యం_ముక్క_mut_201(&commitment));
    Eurydice_arr_ec commitment_hash_candidate = { .దత్తాంశం = { 0U } };
    Eurydice_arr_d2 commitment_serialized = { .దత్తాంశం = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_సదిశ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_కొలత,
      Eurydice_array_గమ్యం_ముక్క_shared_20(&commitment),
      Eurydice_array_గమ్యం_ముక్క_mut_27(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_గమ్యం_ముక్క_shared_17(&సందేశం_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_గమ్యం_ముక్క_shared_27(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_గమ్యం_ముక్క_mut_01(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_గమ్యం_ముక్క_shared_01(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_లోపల_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_9d
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)4U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    Eurydice_arr_9d
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)4U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(Eurydice_array_గమ్యం_ముక్క_mut_201(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(Eurydice_array_గమ్యం_ముక్క_mut_201(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_మాతృక_కూడు_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
      Eurydice_array_గమ్యం_ముక్క_mut_201(&ముసుగు),
      Eurydice_array_గమ్యం_ముక్క_shared_20(&challenge_times_s1));
    libcrux_ml_dsa_మాతృక_వ్యవకలనం_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
      Eurydice_array_గమ్యం_ముక్క_mut_201(&w0),
      Eurydice_array_గమ్యం_ముక్క_shared_20(&challenge_times_s2));
    ఒకవేళ
    (
      !libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_20(&ముసుగు),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
    )
    {
      ఒకవేళ
      (
        !libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_20(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
      )
      {
        Eurydice_arr_9d
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((కొలత_t)4U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_9d);
        libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(Eurydice_array_గమ్యం_ముక్క_mut_201(&challenge_times_t0),
          &verifier_challenge);
        ఒకవేళ
        (
          !libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_20(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2)
        )
        {
          libcrux_ml_dsa_మాతృక_కూడు_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
            Eurydice_array_గమ్యం_ముక్క_mut_201(&w0),
            Eurydice_array_గమ్యం_ముక్క_shared_20(&challenge_times_t0));
          Eurydice_arr_b7
          hint_candidate =
            {
              .దత్తాంశం = {
                { .దత్తాంశం = { 0U } },
                { .దత్తాంశం = { 0U } },
                { .దత్తాంశం = { 0U } },
                { .దత్తాంశం = { 0U } }
              }
            };
          కొలత_t
          ones_లోపల_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_గమ్యం_ముక్క_shared_20(&w0),
              Eurydice_array_గమ్యం_ముక్క_shared_20(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
              Eurydice_array_గమ్యం_ముక్క_mut_86(&hint_candidate));
          ఒకవేళ (!(ones_లోపల_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_లోపల_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_14){
                  .ట్యాగ్ = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_d9){ .ట్యాగ్ = core_option_Some, .f0 = ముసుగు });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_51){
                  .ట్యాగ్ = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_ఫలితం_ఫలితం_53 uu____5;
  ఒకవేళ (commitment_hash0.ట్యాగ్ == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  లేకపోతే
  {
    Eurydice_arr_ec commitment_hash = commitment_hash0.f0;
    Eurydice_arr_ec commitment_hash1 = commitment_hash;
    ఒకవేళ (signer_response0.ట్యాగ్ == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    లేకపోతే
    {
      Eurydice_arr_9d signer_response = signer_response0.f0;
      Eurydice_arr_9d signer_response1 = signer_response;
      ఒకవేళ (!(hint0.ట్యాగ్ == core_option_None))
      {
        Eurydice_arr_b7 hint = hint0.f0;
        Eurydice_arr_b7 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_గమ్యం_ముక్క_shared_01(&commitment_hash1),
          Eurydice_array_గమ్యం_ముక్క_shared_20(&signer_response1),
          Eurydice_array_గమ్యం_ముక్క_shared_86(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_కొలత,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_కొలత,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_లోపల_HINT,
          Eurydice_array_గమ్యం_ముక్క_mut_0d(signature));
        తిరిగి (KRML_CLITERAL(core_ఫలితం_ఫలితం_53){ .ట్యాగ్ = core_ఫలితం_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  తిరిగి uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  core_ఫలితం_ఫలితం_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ట్యాగ్ = core_option_None }));
  ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_అంతర్గత_5a(signing_కీలకం,
      సందేశం_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ట్యాగ్ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_48
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_5a(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_85 signature = libcrux_ml_dsa_types_zero_c5_37();
  core_ఫలితం_ఫలితం_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(signing_కీలకం,
      సందేశం_2,
      context,
      randomness,
      &signature);
  core_ఫలితం_ఫలితం_48 uu____1;
  ఒకవేళ (uu____0.ట్యాగ్ == core_ఫలితం_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_48){
          .ట్యాగ్ = core_ఫలితం_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  లేకపోతే
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ఫలితం_ఫలితం_48){ .ట్యాగ్ = core_ఫలితం_Err, .val = { .case_Err = e } });
  }
  తిరిగి uu____1;
}

/**
 Sign.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_48
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign(
  స్థిరరాశి Eurydice_arr_10 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_5a(Eurydice_array_గమ్యం_ముక్క_shared_34(signing_కీలకం),
      సందేశం_2,
      context,
      randomness);
}

/**
 Sign.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_mut(
  స్థిరరాశి Eurydice_arr_10 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(Eurydice_array_గమ్యం_ముక్క_shared_34(signing_కీలకం),
      సందేశం_2,
      context,
      randomness,
      signature);
}

/**
This function found in impl {libcrux_ml_dsa::pre_hash::PreHash for libcrux_ml_dsa::pre_hash::SHAKE128_PH}
*/
/**
A monomorphic instance of libcrux_ml_dsa.pre_hash.hash_30
with types libcrux_ml_dsa_hash_functions_portable_Shake128
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_pre_hash_hash_30_83(
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_mut_borrow_ముక్క_u8 output
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128_7b(సందేశం_2, output);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_mut_3f(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  ఒకవేళ (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(సందేశం_2, pre_hash_బఫరు);
    core_ఫలితం_ఫలితం_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .ట్యాగ్ = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
    {
      తిరిగి
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    తిరిగి
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_అంతర్గత_5a(signing_కీలకం,
        (
          KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){
            .ptr = pre_hash_బఫరు.ptr,
            .meta = pre_hash_బఫరు.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .ట్యాగ్ = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  తిరిగి
    (
      KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
        .ట్యాగ్ = core_ఫలితం_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_48
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_3f(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_85 signature = libcrux_ml_dsa_types_zero_c5_37();
  core_ఫలితం_ఫలితం_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_mut_3f(signing_కీలకం,
      సందేశం_2,
      context,
      pre_hash_బఫరు,
      randomness,
      &signature);
  core_ఫలితం_ఫలితం_48 uu____1;
  ఒకవేళ (uu____0.ట్యాగ్ == core_ఫలితం_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_48){
          .ట్యాగ్ = core_ఫలితం_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  లేకపోతే
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ఫలితం_ఫలితం_48){ .ట్యాగ్ = core_ఫలితం_Err, .val = { .case_Err = e } });
  }
  తిరిగి uu____1;
}

/**
 Sign (pre-hashed).
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_48
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_10 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_3f(Eurydice_array_గమ్యం_ముక్క_shared_34(signing_కీలకం),
      సందేశం_2,
      context,
      pre_hash_బఫరు,
      randomness);
}

/**
 The internal verification API.

 If no `domain_separation_context` is supplied, it is assumed that
 `message` already contains the domain separation.
*/
/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_అంతర్గత_5a(
  స్థిరరాశి Eurydice_arr_02 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  core_option_Option_84 domain_separation_context,
  స్థిరరాశి Eurydice_arr_85 *signature_serialized
)
{
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_9f(verification_కీలకం),
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_9d t1;
  Eurydice_arr_a3 repeat_expression0[4U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t1.దత్తాంశం, repeat_expression0, (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_కీలకం_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_VERIFICATION_కీలకం_కొలత,
    t1_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_201(&t1));
  Eurydice_arr_ec deserialized_commitment_hash = { .దత్తాంశం = { 0U } };
  Eurydice_arr_9d deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[4U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(deserialized_signer_response.దత్తాంశం,
    repeat_expression1,
    (కొలత_t)4U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_b7
  deserialized_hint =
    { .దత్తాంశం = { { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } } } };
  core_ఫలితం_ఫలితం_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_కొలత,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_కొలత,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_లోపల_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNATURE_కొలత,
      Eurydice_array_గమ్యం_ముక్క_shared_0d(signature_serialized),
      Eurydice_array_గమ్యం_ముక్క_mut_01(&deserialized_commitment_hash),
      Eurydice_array_గమ్యం_ముక్క_mut_201(&deserialized_signer_response),
      Eurydice_array_గమ్యం_ముక్క_mut_86(&deserialized_hint));
  core_ఫలితం_ఫలితం_41 uu____2;
  ఒకవేళ (uu____1.ట్యాగ్ == core_ఫలితం_Ok)
  {
    ఒకవేళ
    (
      libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_20(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    లేకపోతే
    {
      Eurydice_arr_2f మాతృక;
      Eurydice_arr_a3 repeat_వ్యక్తీకరణ[16U];
      కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
      {
        repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      జ్ఞాపకం_నకలు(మాతృక.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)16U * పరిమాణం (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
        విత్తనం_for_a,
        Eurydice_array_గమ్యం_ముక్క_mut_200(&మాతృక));
      Eurydice_arr_c7 verification_కీలకం_hash = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_గమ్యం_ముక్క_shared_9f(verification_కీలకం),
        &verification_కీలకం_hash);
      Eurydice_arr_c7 సందేశం_representative = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_సందేశం_representative_43(Eurydice_array_గమ్యం_ముక్క_shared_17(&verification_కీలకం_hash),
        &domain_separation_context,
        సందేశం_2,
        &సందేశం_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_గమ్యం_ముక్క_shared_01(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_లోపల_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)4U; i++)
      {
        కొలత_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.దత్తాంశం[i0]);
      }
      libcrux_ml_dsa_మాతృక_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_అడ్డువరుసలు_లోపల_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_లోపల_A,
        Eurydice_array_గమ్యం_ముక్క_shared_201(&మాతృక),
        Eurydice_array_గమ్యం_ముక్క_shared_20(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_గమ్యం_ముక్క_mut_201(&t1));
      Eurydice_arr_ec recomputed_commitment_hash = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
        Eurydice_array_గమ్యం_ముక్క_shared_86(&deserialized_hint),
        Eurydice_array_గమ్యం_ముక్క_mut_201(&t1));
      Eurydice_arr_d2 commitment_serialized = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_సదిశ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_కొలత,
        Eurydice_array_గమ్యం_ముక్క_shared_20(&t1),
        Eurydice_array_గమ్యం_ముక్క_mut_27(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_shared_17(&సందేశం_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_shared_27(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_mut_01(&recomputed_commitment_hash));
      ఒకవేళ
      (
        Eurydice_array_eq((కొలత_t)32U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_ఫలితం_ఫలితం_41){ .ట్యాగ్ = core_ఫలితం_Ok });
      }
      లేకపోతే
      {
        uu____2 =
          (
            KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
              .ట్యాగ్ = core_ఫలితం_Err,
              .f0 = libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_సరిపోలిక_Error
            }
          );
      }
    }
  }
  లేకపోతే
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_ఫలితం_ఫలితం_41){ .ట్యాగ్ = core_ఫలితం_Err, .f0 = e });
  }
  తిరిగి uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_5a(
  స్థిరరాశి Eurydice_arr_02 *verification_కీలకం_serialized,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_85 *signature_serialized
)
{
  core_ఫలితం_ఫలితం_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ట్యాగ్ = core_option_None }));
  ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_అంతర్గత_5a(verification_కీలకం_serialized,
      సందేశం_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ట్యాగ్ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify(
  స్థిరరాశి Eurydice_arr_02 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_85 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_5a(verification_కీలకం,
      సందేశం_2,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_pre_hashed_3f(
  స్థిరరాశి Eurydice_arr_02 *verification_కీలకం_serialized,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  స్థిరరాశి Eurydice_arr_85 *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(సందేశం_2, pre_hash_బఫరు);
  core_ఫలితం_ఫలితం_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .ట్యాగ్ = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_అంతర్గత_5a(verification_కీలకం_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){
          .ptr = pre_hash_బఫరు.ptr,
          .meta = pre_hash_బఫరు.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .ట్యాగ్ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_02 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  స్థిరరాశి Eurydice_arr_85 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_pre_hashed_3f(verification_కీలకం,
      సందేశం_2,
      context,
      pre_hash_బఫరు,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_కీలకం_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_mut_borrow_ముక్క_u8 verification_కీలకం
)
{
  Eurydice_arr_89 విత్తనం_expanded0 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .దత్తాంశం = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_mut_78(&విత్తనం_expanded0));
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_78(&విత్తనం_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 విత్తనం_expanded = uu____0.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(విత్తనం_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_ERROR_VECTORS_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_error_vectors = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_signing = uu____1.snd;
  Eurydice_arr_47 s1_s2;
  Eurydice_arr_a3 repeat_expression0[11U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)11U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s1_s2.దత్తాంశం, repeat_expression0, (కొలత_t)11U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    విత్తనం_for_error_vectors,
    Eurydice_array_గమ్యం_ముక్క_mut_202(&s1_s2));
  Eurydice_arr_dc1 t0;
  Eurydice_arr_a3 repeat_expression1[6U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t0.దత్తాంశం, repeat_expression1, (కొలత_t)6U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_5a a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[30U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)30U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(a_as_ntt.దత్తాంశం, repeat_expression2, (కొలత_t)30U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
    విత్తనం_for_a,
    Eurydice_array_గమ్యం_ముక్క_mut_203(&a_as_ntt));
  Eurydice_arr_5d s1_ntt;
  Eurydice_arr_a3 repeat_expression3[5U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)5U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s1_ntt.దత్తాంశం, repeat_expression3, (కొలత_t)5U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_204(&s1_ntt),
    Eurydice_array_గమ్యం_subslice_shared_250(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)0U,
          .చివర = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A
        }
      )),
    Eurydice_arr_a3);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)5U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.దత్తాంశం[i0]);
  }
  libcrux_ml_dsa_మాతృక_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
    Eurydice_array_గమ్యం_ముక్క_mut_203(&a_as_ntt),
    Eurydice_array_గమ్యం_ముక్క_shared_202(&s1_ntt),
    Eurydice_array_గమ్యం_ముక్క_shared_203(&s1_s2),
    Eurydice_array_గమ్యం_ముక్క_mut_205(&t0));
  Eurydice_arr_dc1 t1;
  Eurydice_arr_a3 repeat_వ్యక్తీకరణ[6U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)6U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t1.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)6U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_సదిశ_37(Eurydice_array_గమ్యం_ముక్క_mut_205(&t0),
    Eurydice_array_గమ్యం_ముక్క_mut_205(&t1));
  libcrux_ml_dsa_encoding_verification_కీలకం_generate_serialized_37(విత్తనం_for_a,
    Eurydice_array_గమ్యం_ముక్క_shared_204(&t1),
    verification_కీలకం);
  libcrux_ml_dsa_encoding_signing_కీలకం_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_కొలత,
    విత్తనం_for_a,
    విత్తనం_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){
        .ptr = verification_కీలకం.ptr,
        .meta = verification_కీలకం.meta
      }
    ),
    Eurydice_array_గమ్యం_ముక్క_shared_203(&s1_s2),
    Eurydice_array_గమ్యం_ముక్క_shared_204(&t0),
    signing_కీలకం);
}

/**
 Generate key pair.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_కీలకం_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_24 *signing_కీలకం,
  Eurydice_arr_29 *verification_కీలకం
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_కీలకం_pair_5a(randomness,
    Eurydice_array_గమ్యం_ముక్క_mut_98(signing_కీలకం),
    Eurydice_array_గమ్యం_ముక్క_mut_37(verification_కీలకం));
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_అంతర్గత_5a(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(signing_కీలకం,
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized0 = uu____0.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_SIGNING_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_signing = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized1 = uu____1.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____2 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_బైట్లు_FOR_VERIFICATION_కీలకం_HASH,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 verification_కీలకం_hash = uu____2.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized2 = uu____2.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____3 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_కొలత *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized = uu____3.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____4 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_కొలత *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_ముక్క_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_5d s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[5U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)5U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s1_as_ntt.దత్తాంశం, repeat_expression0, (కొలత_t)5U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_dc1 s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[6U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s2_as_ntt.దత్తాంశం, repeat_expression1, (కొలత_t)6U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_dc1 t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[6U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)6U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t0_as_ntt.దత్తాంశం, repeat_expression2, (కొలత_t)6U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_గమ్యం_సదిశ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_కొలత,
    s1_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_204(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_గమ్యం_సదిశ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_కొలత,
    s2_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_205(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_గమ్యం_సదిశ_then_ntt_37(t0_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_205(&t0_as_ntt));
  Eurydice_arr_5a మాతృక;
  Eurydice_arr_a3 repeat_expression3[30U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)30U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(మాతృక.దత్తాంశం, repeat_expression3, (కొలత_t)30U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
    విత్తనం_for_a,
    Eurydice_array_గమ్యం_ముక్క_mut_203(&మాతృక));
  Eurydice_arr_c7 సందేశం_representative = { .దత్తాంశం = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_సందేశం_representative_43(verification_కీలకం_hash,
    &domain_separation_context,
    సందేశం_2,
    &సందేశం_representative);
  Eurydice_arr_c7 ముసుగు_విత్తనం = { .దత్తాంశం = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, విత్తనం_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_గమ్యం_ముక్క_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_గమ్యం_ముక్క_shared_17(&సందేశం_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_గమ్యం_ముక్క_mut_17(&ముసుగు_విత్తనం));
  uint16_t domain_separator_for_ముసుగు = 0U;
  కొలత_t attempt = (కొలత_t)0U;
  core_option_Option_81 commitment_hash0 = { .ట్యాగ్ = core_option_None };
  core_option_Option_1e signer_response0 = { .ట్యాగ్ = core_option_None };
  core_option_Option_05 hint0 = { .ట్యాగ్ = core_option_None };
  అయితే (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_5d ముసుగు;
    Eurydice_arr_a3 repeat_expression4[5U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)5U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(ముసుగు.దత్తాంశం, repeat_expression4, (కొలత_t)5U * పరిమాణం (Eurydice_arr_a3));
    Eurydice_arr_dc1 w0;
    Eurydice_arr_a3 repeat_expression5[6U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)6U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(w0.దత్తాంశం, repeat_expression5, (కొలత_t)6U * పరిమాణం (Eurydice_arr_a3));
    Eurydice_arr_dc1 commitment;
    Eurydice_arr_a3 repeat_expression6[6U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)6U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(commitment.దత్తాంశం, repeat_expression6, (కొలత_t)6U * పరిమాణం (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_ముసుగు_సదిశ_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      &ముసుగు_విత్తనం,
      &domain_separator_for_ముసుగు,
      Eurydice_array_గమ్యం_ముక్క_mut_204(&ముసుగు));
    Eurydice_arr_dc1 a_x_ముసుగు;
    Eurydice_arr_a3 repeat_వ్యక్తీకరణ[6U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)6U; i++)
    {
      repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(a_x_ముసుగు.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)6U * పరిమాణం (Eurydice_arr_a3));
    Eurydice_arr_5d
    ముసుగు_ntt =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)5U,
        &ముసుగు,
        Eurydice_arr_a3,
        Eurydice_arr_5d);
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)5U; i++)
    {
      కొలత_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&ముసుగు_ntt.దత్తాంశం[i0]);
    }
    libcrux_ml_dsa_మాతృక_compute_మాతృక_x_ముసుగు_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
      Eurydice_array_గమ్యం_ముక్క_shared_205(&మాతృక),
      Eurydice_array_గమ్యం_ముక్క_shared_202(&ముసుగు_ntt),
      Eurydice_array_గమ్యం_ముక్క_mut_205(&a_x_ముసుగు));
    libcrux_ml_dsa_arithmetic_decompose_సదిశ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
      Eurydice_array_గమ్యం_ముక్క_shared_204(&a_x_ముసుగు),
      Eurydice_array_గమ్యం_ముక్క_mut_205(&w0),
      Eurydice_array_గమ్యం_ముక్క_mut_205(&commitment));
    Eurydice_arr_65 commitment_hash_candidate = { .దత్తాంశం = { 0U } };
    Eurydice_arr_d2 commitment_serialized = { .దత్తాంశం = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_సదిశ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_కొలత,
      Eurydice_array_గమ్యం_ముక్క_shared_204(&commitment),
      Eurydice_array_గమ్యం_ముక్క_mut_27(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_గమ్యం_ముక్క_shared_17(&సందేశం_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_గమ్యం_ముక్క_shared_27(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_గమ్యం_ముక్క_mut_9f(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_గమ్యం_ముక్క_shared_9f0(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_లోపల_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_5d
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)5U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_5d);
    Eurydice_arr_dc1
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)6U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_dc1);
    libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(Eurydice_array_గమ్యం_ముక్క_mut_204(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(Eurydice_array_గమ్యం_ముక్క_mut_205(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_మాతృక_కూడు_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
      Eurydice_array_గమ్యం_ముక్క_mut_204(&ముసుగు),
      Eurydice_array_గమ్యం_ముక్క_shared_202(&challenge_times_s1));
    libcrux_ml_dsa_మాతృక_వ్యవకలనం_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
      Eurydice_array_గమ్యం_ముక్క_mut_205(&w0),
      Eurydice_array_గమ్యం_ముక్క_shared_204(&challenge_times_s2));
    ఒకవేళ
    (
      !libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_202(&ముసుగు),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      ఒకవేళ
      (
        !libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_204(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
      )
      {
        Eurydice_arr_dc1
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((కొలత_t)6U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_dc1);
        libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(Eurydice_array_గమ్యం_ముక్క_mut_205(&challenge_times_t0),
          &verifier_challenge);
        ఒకవేళ
        (
          !libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_204(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2)
        )
        {
          libcrux_ml_dsa_మాతృక_కూడు_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
            Eurydice_array_గమ్యం_ముక్క_mut_205(&w0),
            Eurydice_array_గమ్యం_ముక్క_shared_204(&challenge_times_t0));
          Eurydice_arr_5d0
          hint_candidate =
            {
              .దత్తాంశం = {
                { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } },
                { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }
              }
            };
          కొలత_t
          ones_లోపల_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_గమ్యం_ముక్క_shared_204(&w0),
              Eurydice_array_గమ్యం_ముక్క_shared_204(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
              Eurydice_array_గమ్యం_ముక్క_mut_860(&hint_candidate));
          ఒకవేళ (!(ones_లోపల_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_లోపల_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_81){
                  .ట్యాగ్ = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_1e){ .ట్యాగ్ = core_option_Some, .f0 = ముసుగు });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_05){
                  .ట్యాగ్ = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_ఫలితం_ఫలితం_53 uu____5;
  ఒకవేళ (commitment_hash0.ట్యాగ్ == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  లేకపోతే
  {
    Eurydice_arr_65 commitment_hash = commitment_hash0.f0;
    Eurydice_arr_65 commitment_hash1 = commitment_hash;
    ఒకవేళ (signer_response0.ట్యాగ్ == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    లేకపోతే
    {
      Eurydice_arr_5d signer_response = signer_response0.f0;
      Eurydice_arr_5d signer_response1 = signer_response;
      ఒకవేళ (!(hint0.ట్యాగ్ == core_option_None))
      {
        Eurydice_arr_5d0 hint = hint0.f0;
        Eurydice_arr_5d0 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_గమ్యం_ముక్క_shared_9f0(&commitment_hash1),
          Eurydice_array_గమ్యం_ముక్క_shared_202(&signer_response1),
          Eurydice_array_గమ్యం_ముక్క_shared_860(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_కొలత,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_కొలత,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_లోపల_HINT,
          Eurydice_array_గమ్యం_ముక్క_mut_6b(signature));
        తిరిగి (KRML_CLITERAL(core_ఫలితం_ఫలితం_53){ .ట్యాగ్ = core_ఫలితం_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  తిరిగి uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  core_ఫలితం_ఫలితం_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ట్యాగ్ = core_option_None }));
  ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_అంతర్గత_5a(signing_కీలకం,
      సందేశం_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ట్యాగ్ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_8c
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_0c signature = libcrux_ml_dsa_types_zero_c5_5c();
  core_ఫలితం_ఫలితం_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(signing_కీలకం,
      సందేశం_2,
      context,
      randomness,
      &signature);
  core_ఫలితం_ఫలితం_8c uu____1;
  ఒకవేళ (uu____0.ట్యాగ్ == core_ఫలితం_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_8c){
          .ట్యాగ్ = core_ఫలితం_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  లేకపోతే
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ఫలితం_ఫలితం_8c){ .ట్యాగ్ = core_ఫలితం_Err, .val = { .case_Err = e } });
  }
  తిరిగి uu____1;
}

/**
 Sign.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_8c
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(
  స్థిరరాశి Eurydice_arr_24 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(Eurydice_array_గమ్యం_ముక్క_shared_98(signing_కీలకం),
      సందేశం_2,
      context,
      randomness);
}

/**
 Sign.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(
  స్థిరరాశి Eurydice_arr_24 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(Eurydice_array_గమ్యం_ముక్క_shared_98(signing_కీలకం),
      సందేశం_2,
      context,
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  ఒకవేళ (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(సందేశం_2, pre_hash_బఫరు);
    core_ఫలితం_ఫలితం_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .ట్యాగ్ = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
    {
      తిరిగి
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    తిరిగి
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_అంతర్గత_5a(signing_కీలకం,
        (
          KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){
            .ptr = pre_hash_బఫరు.ptr,
            .meta = pre_hash_బఫరు.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .ట్యాగ్ = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  తిరిగి
    (
      KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
        .ట్యాగ్ = core_ఫలితం_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_8c
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_0c signature = libcrux_ml_dsa_types_zero_c5_5c();
  core_ఫలితం_ఫలితం_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(signing_కీలకం,
      సందేశం_2,
      context,
      pre_hash_బఫరు,
      randomness,
      &signature);
  core_ఫలితం_ఫలితం_8c uu____1;
  ఒకవేళ (uu____0.ట్యాగ్ == core_ఫలితం_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_8c){
          .ట్యాగ్ = core_ఫలితం_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  లేకపోతే
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ఫలితం_ఫలితం_8c){ .ట్యాగ్ = core_ఫలితం_Err, .val = { .case_Err = e } });
  }
  తిరిగి uu____1;
}

/**
 Sign (pre-hashed).
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_8c
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_24 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(Eurydice_array_గమ్యం_ముక్క_shared_98(signing_కీలకం),
      సందేశం_2,
      context,
      pre_hash_బఫరు,
      randomness);
}

/**
 The internal verification API.

 If no `domain_separation_context` is supplied, it is assumed that
 `message` already contains the domain separation.
*/
/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_అంతర్గత_5a(
  స్థిరరాశి Eurydice_arr_29 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  core_option_Option_84 domain_separation_context,
  స్థిరరాశి Eurydice_arr_0c *signature_serialized
)
{
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_37(verification_కీలకం),
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_dc1 t1;
  Eurydice_arr_a3 repeat_expression0[6U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)6U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t1.దత్తాంశం, repeat_expression0, (కొలత_t)6U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_కీలకం_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_కీలకం_కొలత,
    t1_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_205(&t1));
  Eurydice_arr_65 deserialized_commitment_hash = { .దత్తాంశం = { 0U } };
  Eurydice_arr_5d deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[5U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)5U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(deserialized_signer_response.దత్తాంశం,
    repeat_expression1,
    (కొలత_t)5U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_5d0
  deserialized_hint =
    {
      .దత్తాంశం = {
        { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } },
        { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }
      }
    };
  core_ఫలితం_ఫలితం_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_కొలత,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_కొలత,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_లోపల_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_కొలత,
      Eurydice_array_గమ్యం_ముక్క_shared_6b(signature_serialized),
      Eurydice_array_గమ్యం_ముక్క_mut_9f(&deserialized_commitment_hash),
      Eurydice_array_గమ్యం_ముక్క_mut_204(&deserialized_signer_response),
      Eurydice_array_గమ్యం_ముక్క_mut_860(&deserialized_hint));
  core_ఫలితం_ఫలితం_41 uu____2;
  ఒకవేళ (uu____1.ట్యాగ్ == core_ఫలితం_Ok)
  {
    ఒకవేళ
    (
      libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_202(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    లేకపోతే
    {
      Eurydice_arr_5a మాతృక;
      Eurydice_arr_a3 repeat_వ్యక్తీకరణ[30U];
      కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)30U; i++)
      {
        repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      జ్ఞాపకం_నకలు(మాతృక.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)30U * పరిమాణం (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
        విత్తనం_for_a,
        Eurydice_array_గమ్యం_ముక్క_mut_203(&మాతృక));
      Eurydice_arr_c7 verification_కీలకం_hash = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_గమ్యం_ముక్క_shared_37(verification_కీలకం),
        &verification_కీలకం_hash);
      Eurydice_arr_c7 సందేశం_representative = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_సందేశం_representative_43(Eurydice_array_గమ్యం_ముక్క_shared_17(&verification_కీలకం_hash),
        &domain_separation_context,
        సందేశం_2,
        &సందేశం_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_గమ్యం_ముక్క_shared_9f0(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_లోపల_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)5U; i++)
      {
        కొలత_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.దత్తాంశం[i0]);
      }
      libcrux_ml_dsa_మాతృక_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_అడ్డువరుసలు_లోపల_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_లోపల_A,
        Eurydice_array_గమ్యం_ముక్క_shared_205(&మాతృక),
        Eurydice_array_గమ్యం_ముక్క_shared_202(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_గమ్యం_ముక్క_mut_205(&t1));
      Eurydice_arr_65 recomputed_commitment_hash = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
        Eurydice_array_గమ్యం_ముక్క_shared_860(&deserialized_hint),
        Eurydice_array_గమ్యం_ముక్క_mut_205(&t1));
      Eurydice_arr_d2 commitment_serialized = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_సదిశ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_కొలత,
        Eurydice_array_గమ్యం_ముక్క_shared_204(&t1),
        Eurydice_array_గమ్యం_ముక్క_mut_27(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_shared_17(&సందేశం_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_shared_27(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_mut_9f(&recomputed_commitment_hash));
      ఒకవేళ
      (
        Eurydice_array_eq((కొలత_t)48U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_ఫలితం_ఫలితం_41){ .ట్యాగ్ = core_ఫలితం_Ok });
      }
      లేకపోతే
      {
        uu____2 =
          (
            KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
              .ట్యాగ్ = core_ఫలితం_Err,
              .f0 = libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_సరిపోలిక_Error
            }
          );
      }
    }
  }
  లేకపోతే
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_ఫలితం_ఫలితం_41){ .ట్యాగ్ = core_ఫలితం_Err, .f0 = e });
  }
  తిరిగి uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(
  స్థిరరాశి Eurydice_arr_29 *verification_కీలకం_serialized,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_0c *signature_serialized
)
{
  core_ఫలితం_ఫలితం_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ట్యాగ్ = core_option_None }));
  ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_అంతర్గత_5a(verification_కీలకం_serialized,
      సందేశం_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ట్యాగ్ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(
  స్థిరరాశి Eurydice_arr_29 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_0c *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(verification_కీలకం,
      సందేశం_2,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(
  స్థిరరాశి Eurydice_arr_29 *verification_కీలకం_serialized,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  స్థిరరాశి Eurydice_arr_0c *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(సందేశం_2, pre_hash_బఫరు);
  core_ఫలితం_ఫలితం_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .ట్యాగ్ = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_అంతర్గత_5a(verification_కీలకం_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){
          .ptr = pre_hash_బఫరు.ptr,
          .meta = pre_hash_బఫరు.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .ట్యాగ్ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_29 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  స్థిరరాశి Eurydice_arr_0c *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(verification_కీలకం,
      సందేశం_2,
      context,
      pre_hash_బఫరు,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_generate_కీలకం_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_mut_borrow_ముక్క_u8 verification_కీలకం
)
{
  Eurydice_arr_89 విత్తనం_expanded0 = { .దత్తాంశం = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .దత్తాంశం = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_గమ్యం_ముక్క_mut_78(&విత్తనం_expanded0));
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_78(&విత్తనం_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 విత్తనం_expanded = uu____0.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(విత్తనం_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_ERROR_VECTORS_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_error_vectors = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_signing = uu____1.snd;
  Eurydice_arr_92 s1_s2;
  Eurydice_arr_a3 repeat_expression0[15U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)15U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s1_s2.దత్తాంశం, repeat_expression0, (కొలత_t)15U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    విత్తనం_for_error_vectors,
    Eurydice_array_గమ్యం_ముక్క_mut_206(&s1_s2));
  Eurydice_arr_8f t0;
  Eurydice_arr_a3 repeat_expression1[8U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t0.దత్తాంశం, repeat_expression1, (కొలత_t)8U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_0f a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[56U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)56U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(a_as_ntt.దత్తాంశం, repeat_expression2, (కొలత_t)56U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
    విత్తనం_for_a,
    Eurydice_array_గమ్యం_ముక్క_mut_207(&a_as_ntt));
  Eurydice_arr_bb s1_ntt;
  Eurydice_arr_a3 repeat_expression3[7U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)7U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s1_ntt.దత్తాంశం, repeat_expression3, (కొలత_t)7U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_208(&s1_ntt),
    Eurydice_array_గమ్యం_subslice_shared_251(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)0U,
          .చివర = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A
        }
      )),
    Eurydice_arr_a3);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)7U; i++)
  {
    కొలత_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.దత్తాంశం[i0]);
  }
  libcrux_ml_dsa_మాతృక_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
    Eurydice_array_గమ్యం_ముక్క_mut_207(&a_as_ntt),
    Eurydice_array_గమ్యం_ముక్క_shared_206(&s1_ntt),
    Eurydice_array_గమ్యం_ముక్క_shared_207(&s1_s2),
    Eurydice_array_గమ్యం_ముక్క_mut_20(&t0));
  Eurydice_arr_8f t1;
  Eurydice_arr_a3 repeat_వ్యక్తీకరణ[8U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t1.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)8U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_సదిశ_37(Eurydice_array_గమ్యం_ముక్క_mut_20(&t0),
    Eurydice_array_గమ్యం_ముక్క_mut_20(&t1));
  libcrux_ml_dsa_encoding_verification_కీలకం_generate_serialized_37(విత్తనం_for_a,
    Eurydice_array_గమ్యం_ముక్క_shared_200(&t1),
    verification_కీలకం);
  libcrux_ml_dsa_encoding_signing_కీలకం_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_కొలత,
    విత్తనం_for_a,
    విత్తనం_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){
        .ptr = verification_కీలకం.ptr,
        .meta = verification_కీలకం.meta
      }
    ),
    Eurydice_array_గమ్యం_ముక్క_shared_207(&s1_s2),
    Eurydice_array_గమ్యం_ముక్క_shared_200(&t0),
    signing_కీలకం);
}

/**
 Generate key pair.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_generate_కీలకం_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_e2 *signing_కీలకం,
  Eurydice_arr_43 *verification_కీలకం
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_generate_కీలకం_pair_5a(randomness,
    Eurydice_array_గమ్యం_ముక్క_mut_f7(signing_కీలకం),
    Eurydice_array_గమ్యం_ముక్క_mut_fc(verification_కీలకం));
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_అంతర్గత_5a(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(signing_కీలకం,
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized0 = uu____0.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_SIGNING_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_signing = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized1 = uu____1.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____2 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_బైట్లు_FOR_VERIFICATION_కీలకం_HASH,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 verification_కీలకం_hash = uu____2.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized2 = uu____2.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____3 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_కొలత *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_ముక్క_u8 మిగిలిన_serialized = uu____3.snd;
  Eurydice_borrow_ముక్క_u8_x2
  uu____4 =
    Eurydice_ముక్క_విభజించు_at(మిగిలిన_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_కొలత *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_ముక్క_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_bb s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[7U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)7U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s1_as_ntt.దత్తాంశం, repeat_expression0, (కొలత_t)7U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_8f s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[8U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(s2_as_ntt.దత్తాంశం, repeat_expression1, (కొలత_t)8U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_8f t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[8U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t0_as_ntt.దత్తాంశం, repeat_expression2, (కొలత_t)8U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_గమ్యం_సదిశ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_కొలత,
    s1_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_208(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_గమ్యం_సదిశ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_కొలత,
    s2_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_20(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_గమ్యం_సదిశ_then_ntt_37(t0_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_20(&t0_as_ntt));
  Eurydice_arr_0f మాతృక;
  Eurydice_arr_a3 repeat_expression3[56U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)56U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(మాతృక.దత్తాంశం, repeat_expression3, (కొలత_t)56U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
    విత్తనం_for_a,
    Eurydice_array_గమ్యం_ముక్క_mut_207(&మాతృక));
  Eurydice_arr_c7 సందేశం_representative = { .దత్తాంశం = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_సందేశం_representative_43(verification_కీలకం_hash,
    &domain_separation_context,
    సందేశం_2,
    &సందేశం_representative);
  Eurydice_arr_c7 ముసుగు_విత్తనం = { .దత్తాంశం = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, విత్తనం_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_గమ్యం_ముక్క_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_గమ్యం_ముక్క_shared_17(&సందేశం_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_గమ్యం_ముక్క_mut_17(&ముసుగు_విత్తనం));
  uint16_t domain_separator_for_ముసుగు = 0U;
  కొలత_t attempt = (కొలత_t)0U;
  core_option_Option_b2 commitment_hash0 = { .ట్యాగ్ = core_option_None };
  core_option_Option_2d signer_response0 = { .ట్యాగ్ = core_option_None };
  core_option_Option_45 hint0 = { .ట్యాగ్ = core_option_None };
  అయితే (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_bb ముసుగు;
    Eurydice_arr_a3 repeat_expression4[7U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)7U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(ముసుగు.దత్తాంశం, repeat_expression4, (కొలత_t)7U * పరిమాణం (Eurydice_arr_a3));
    Eurydice_arr_8f w0;
    Eurydice_arr_a3 repeat_expression5[8U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(w0.దత్తాంశం, repeat_expression5, (కొలత_t)8U * పరిమాణం (Eurydice_arr_a3));
    Eurydice_arr_8f commitment;
    Eurydice_arr_a3 repeat_expression6[8U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(commitment.దత్తాంశం, repeat_expression6, (కొలత_t)8U * పరిమాణం (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_ముసుగు_సదిశ_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
      &ముసుగు_విత్తనం,
      &domain_separator_for_ముసుగు,
      Eurydice_array_గమ్యం_ముక్క_mut_208(&ముసుగు));
    Eurydice_arr_8f a_x_ముసుగు;
    Eurydice_arr_a3 repeat_వ్యక్తీకరణ[8U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
    {
      repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    జ్ఞాపకం_నకలు(a_x_ముసుగు.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)8U * పరిమాణం (Eurydice_arr_a3));
    Eurydice_arr_bb
    ముసుగు_ntt =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)7U,
        &ముసుగు,
        Eurydice_arr_a3,
        Eurydice_arr_bb);
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)7U; i++)
    {
      కొలత_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&ముసుగు_ntt.దత్తాంశం[i0]);
    }
    libcrux_ml_dsa_మాతృక_compute_మాతృక_x_ముసుగు_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
      Eurydice_array_గమ్యం_ముక్క_shared_208(&మాతృక),
      Eurydice_array_గమ్యం_ముక్క_shared_206(&ముసుగు_ntt),
      Eurydice_array_గమ్యం_ముక్క_mut_20(&a_x_ముసుగు));
    libcrux_ml_dsa_arithmetic_decompose_సదిశ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
      Eurydice_array_గమ్యం_ముక్క_shared_200(&a_x_ముసుగు),
      Eurydice_array_గమ్యం_ముక్క_mut_20(&w0),
      Eurydice_array_గమ్యం_ముక్క_mut_20(&commitment));
    Eurydice_arr_c7 commitment_hash_candidate = { .దత్తాంశం = { 0U } };
    Eurydice_arr_1b commitment_serialized = { .దత్తాంశం = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_సదిశ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_కొలత,
      Eurydice_array_గమ్యం_ముక్క_shared_200(&commitment),
      Eurydice_array_గమ్యం_ముక్క_mut_68(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_గమ్యం_ముక్క_shared_17(&సందేశం_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_గమ్యం_ముక్క_shared_68(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_గమ్యం_ముక్క_mut_17(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_గమ్యం_ముక్క_shared_17(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_లోపల_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_bb
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)7U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_bb);
    Eurydice_arr_8f
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)8U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_8f);
    libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(Eurydice_array_గమ్యం_ముక్క_mut_208(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(Eurydice_array_గమ్యం_ముక్క_mut_20(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_మాతృక_కూడు_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
      Eurydice_array_గమ్యం_ముక్క_mut_208(&ముసుగు),
      Eurydice_array_గమ్యం_ముక్క_shared_206(&challenge_times_s1));
    libcrux_ml_dsa_మాతృక_వ్యవకలనం_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
      Eurydice_array_గమ్యం_ముక్క_mut_20(&w0),
      Eurydice_array_గమ్యం_ముక్క_shared_200(&challenge_times_s2));
    ఒకవేళ
    (
      !libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_206(&ముసుగు),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
    )
    {
      ఒకవేళ
      (
        !libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_200(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
      )
      {
        Eurydice_arr_8f
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((కొలత_t)8U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_8f);
        libcrux_ml_dsa_మాతృక_సదిశ_times_ring_element_37(Eurydice_array_గమ్యం_ముక్క_mut_20(&challenge_times_t0),
          &verifier_challenge);
        ఒకవేళ
        (
          !libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_200(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2)
        )
        {
          libcrux_ml_dsa_మాతృక_కూడు_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
            Eurydice_array_గమ్యం_ముక్క_mut_20(&w0),
            Eurydice_array_గమ్యం_ముక్క_shared_200(&challenge_times_t0));
          Eurydice_arr_81
          hint_candidate =
            {
              .దత్తాంశం = {
                { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } },
                { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }
              }
            };
          కొలత_t
          ones_లోపల_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_గమ్యం_ముక్క_shared_200(&w0),
              Eurydice_array_గమ్యం_ముక్క_shared_200(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
              Eurydice_array_గమ్యం_ముక్క_mut_861(&hint_candidate));
          ఒకవేళ (!(ones_లోపల_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_లోపల_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_b2){
                  .ట్యాగ్ = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_2d){ .ట్యాగ్ = core_option_Some, .f0 = ముసుగు });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_45){
                  .ట్యాగ్ = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_ఫలితం_ఫలితం_53 uu____5;
  ఒకవేళ (commitment_hash0.ట్యాగ్ == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  లేకపోతే
  {
    Eurydice_arr_c7 commitment_hash = commitment_hash0.f0;
    Eurydice_arr_c7 commitment_hash1 = commitment_hash;
    ఒకవేళ (signer_response0.ట్యాగ్ == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    లేకపోతే
    {
      Eurydice_arr_bb signer_response = signer_response0.f0;
      Eurydice_arr_bb signer_response1 = signer_response;
      ఒకవేళ (!(hint0.ట్యాగ్ == core_option_None))
      {
        Eurydice_arr_81 hint = hint0.f0;
        Eurydice_arr_81 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_గమ్యం_ముక్క_shared_17(&commitment_hash1),
          Eurydice_array_గమ్యం_ముక్క_shared_206(&signer_response1),
          Eurydice_array_గమ్యం_ముక్క_shared_861(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_కొలత,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_కొలత,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_లోపల_HINT,
          Eurydice_array_గమ్యం_ముక్క_mut_11(signature));
        తిరిగి (KRML_CLITERAL(core_ఫలితం_ఫలితం_53){ .ట్యాగ్ = core_ఫలితం_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  తిరిగి uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  core_ఫలితం_ఫలితం_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ట్యాగ్ = core_option_None }));
  ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_అంతర్గత_5a(signing_కీలకం,
      సందేశం_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ట్యాగ్ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_8b
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_5a(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_93 signature = libcrux_ml_dsa_types_zero_c5_f1();
  core_ఫలితం_ఫలితం_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(signing_కీలకం,
      సందేశం_2,
      context,
      randomness,
      &signature);
  core_ఫలితం_ఫలితం_8b uu____1;
  ఒకవేళ (uu____0.ట్యాగ్ == core_ఫలితం_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_8b){
          .ట్యాగ్ = core_ఫలితం_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  లేకపోతే
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ఫలితం_ఫలితం_8b){ .ట్యాగ్ = core_ఫలితం_Err, .val = { .case_Err = e } });
  }
  తిరిగి uu____1;
}

/**
 Sign.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_8b
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign(
  స్థిరరాశి Eurydice_arr_e2 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_5a(Eurydice_array_గమ్యం_ముక్క_shared_f7(signing_కీలకం),
      సందేశం_2,
      context,
      randomness);
}

/**
 Sign.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_mut(
  స్థిరరాశి Eurydice_arr_e2 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(Eurydice_array_గమ్యం_ముక్క_shared_f7(signing_కీలకం),
      సందేశం_2,
      context,
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_mut_3f(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  ఒకవేళ (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(సందేశం_2, pre_hash_బఫరు);
    core_ఫలితం_ఫలితం_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .ట్యాగ్ = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
    {
      తిరిగి
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    తిరిగి
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_అంతర్గత_5a(signing_కీలకం,
        (
          KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){
            .ptr = pre_hash_బఫరు.ptr,
            .meta = pre_hash_బఫరు.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .ట్యాగ్ = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  తిరిగి
    (
      KRML_CLITERAL(core_ఫలితం_ఫలితం_53){
        .ట్యాగ్ = core_ఫలితం_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_8b
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_3f(
  Eurydice_borrow_ముక్క_u8 signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_93 signature = libcrux_ml_dsa_types_zero_c5_f1();
  core_ఫలితం_ఫలితం_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_mut_3f(signing_కీలకం,
      సందేశం_2,
      context,
      pre_hash_బఫరు,
      randomness,
      &signature);
  core_ఫలితం_ఫలితం_8b uu____1;
  ఒకవేళ (uu____0.ట్యాగ్ == core_ఫలితం_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_8b){
          .ట్యాగ్ = core_ఫలితం_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  లేకపోతే
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ఫలితం_ఫలితం_8b){ .ట్యాగ్ = core_ఫలితం_Err, .val = { .case_Err = e } });
  }
  తిరిగి uu____1;
}

/**
 Sign (pre-hashed).
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_8b
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_e2 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_3f(Eurydice_array_గమ్యం_ముక్క_shared_f7(signing_కీలకం),
      సందేశం_2,
      context,
      pre_hash_బఫరు,
      randomness);
}

/**
 The internal verification API.

 If no `domain_separation_context` is supplied, it is assumed that
 `message` already contains the domain separation.
*/
/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_అంతర్గత_5a(
  స్థిరరాశి Eurydice_arr_43 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  core_option_Option_84 domain_separation_context,
  స్థిరరాశి Eurydice_arr_93 *signature_serialized
)
{
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_fc(verification_కీలకం),
      LIBCRUX_ML_DSA_CONSTANTS_విత్తనం_FOR_A_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_8f t1;
  Eurydice_arr_a3 repeat_expression0[8U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)8U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(t1.దత్తాంశం, repeat_expression0, (కొలత_t)8U * పరిమాణం (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_కీలకం_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_VERIFICATION_కీలకం_కొలత,
    t1_serialized,
    Eurydice_array_గమ్యం_ముక్క_mut_20(&t1));
  Eurydice_arr_c7 deserialized_commitment_hash = { .దత్తాంశం = { 0U } };
  Eurydice_arr_bb deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[7U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)7U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  జ్ఞాపకం_నకలు(deserialized_signer_response.దత్తాంశం,
    repeat_expression1,
    (కొలత_t)7U * పరిమాణం (Eurydice_arr_a3));
  Eurydice_arr_81
  deserialized_hint =
    {
      .దత్తాంశం = {
        { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } },
        { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }
      }
    };
  core_ఫలితం_ఫలితం_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_కొలత,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_కొలత,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_లోపల_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNATURE_కొలత,
      Eurydice_array_గమ్యం_ముక్క_shared_11(signature_serialized),
      Eurydice_array_గమ్యం_ముక్క_mut_17(&deserialized_commitment_hash),
      Eurydice_array_గమ్యం_ముక్క_mut_208(&deserialized_signer_response),
      Eurydice_array_గమ్యం_ముక్క_mut_861(&deserialized_hint));
  core_ఫలితం_ఫలితం_41 uu____2;
  ఒకవేళ (uu____1.ట్యాగ్ == core_ఫలితం_Ok)
  {
    ఒకవేళ
    (
      libcrux_ml_dsa_arithmetic_సదిశ_infinity_norm_exceeds_37(Eurydice_array_గమ్యం_ముక్క_shared_206(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
            .ట్యాగ్ = core_ఫలితం_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    లేకపోతే
    {
      Eurydice_arr_0f మాతృక;
      Eurydice_arr_a3 repeat_వ్యక్తీకరణ[56U];
      కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)56U; i++)
      {
        repeat_వ్యక్తీకరణ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      జ్ఞాపకం_నకలు(మాతృక.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)56U * పరిమాణం (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_మాతృక_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
        విత్తనం_for_a,
        Eurydice_array_గమ్యం_ముక్క_mut_207(&మాతృక));
      Eurydice_arr_c7 verification_కీలకం_hash = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_గమ్యం_ముక్క_shared_fc(verification_కీలకం),
        &verification_కీలకం_hash);
      Eurydice_arr_c7 సందేశం_representative = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_సందేశం_representative_43(Eurydice_array_గమ్యం_ముక్క_shared_17(&verification_కీలకం_hash),
        &domain_separation_context,
        సందేశం_2,
        &సందేశం_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_గమ్యం_ముక్క_shared_17(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_లోపల_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)7U; i++)
      {
        కొలత_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.దత్తాంశం[i0]);
      }
      libcrux_ml_dsa_మాతృక_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_అడ్డువరుసలు_లోపల_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_లోపల_A,
        Eurydice_array_గమ్యం_ముక్క_shared_208(&మాతృక),
        Eurydice_array_గమ్యం_ముక్క_shared_206(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_గమ్యం_ముక్క_mut_20(&t1));
      Eurydice_arr_c7 recomputed_commitment_hash = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
        Eurydice_array_గమ్యం_ముక్క_shared_861(&deserialized_hint),
        Eurydice_array_గమ్యం_ముక్క_mut_20(&t1));
      Eurydice_arr_1b commitment_serialized = { .దత్తాంశం = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_సదిశ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_కొలత,
        Eurydice_array_గమ్యం_ముక్క_shared_200(&t1),
        Eurydice_array_గమ్యం_ముక్క_mut_68(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_shared_17(&సందేశం_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_shared_68(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_గమ్యం_ముక్క_mut_17(&recomputed_commitment_hash));
      ఒకవేళ
      (
        Eurydice_array_eq((కొలత_t)64U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_ఫలితం_ఫలితం_41){ .ట్యాగ్ = core_ఫలితం_Ok });
      }
      లేకపోతే
      {
        uu____2 =
          (
            KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
              .ట్యాగ్ = core_ఫలితం_Err,
              .f0 = libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_సరిపోలిక_Error
            }
          );
      }
    }
  }
  లేకపోతే
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_ఫలితం_ఫలితం_41){ .ట్యాగ్ = core_ఫలితం_Err, .f0 = e });
  }
  తిరిగి uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_5a(
  స్థిరరాశి Eurydice_arr_43 *verification_కీలకం_serialized,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_93 *signature_serialized
)
{
  core_ఫలితం_ఫలితం_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ట్యాగ్ = core_option_None }));
  ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_అంతర్గత_5a(verification_కీలకం_serialized,
      సందేశం_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ట్యాగ్ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify(
  స్థిరరాశి Eurydice_arr_43 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_93 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_5a(verification_కీలకం,
      సందేశం_2,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
స్థిర KRML_MUSTINLINE core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_pre_hashed_3f(
  స్థిరరాశి Eurydice_arr_43 *verification_కీలకం_serialized,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  స్థిరరాశి Eurydice_arr_93 *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(సందేశం_2, pre_hash_బఫరు);
  core_ఫలితం_ఫలితం_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .ట్యాగ్ = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  ఒకవేళ (!(uu____0.ట్యాగ్ == core_ఫలితం_Ok))
  {
    తిరిగి
      (
        KRML_CLITERAL(core_ఫలితం_ఫలితం_41){
          .ట్యాగ్ = core_ఫలితం_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_అంతర్గత_5a(verification_కీలకం_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_ముక్క_u8){
          .ptr = pre_hash_బఫరు.ptr,
          .meta = pre_hash_బఫరు.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .ట్యాగ్ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_43 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_mut_borrow_ముక్క_u8 pre_hash_బఫరు,
  స్థిరరాశి Eurydice_arr_93 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_pre_hashed_3f(verification_కీలకం,
      సందేశం_2,
      context,
      pre_hash_బఫరు,
      signature);
}

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు libcrux_mldsa_portable_H_DEFINED
#అయితే_ముగింపు /* libcrux_mldsa_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa44_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే libcrux_mldsa44_portable_H
#నిర్వచించు libcrux_mldsa44_portable_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


/**
 Generate an ML-DSA-44 Key Pair
*/
స్థిర అంతఃవరుస libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_కీలకం_Pair
libcrux_ml_dsa_ml_dsa_44_portable_generate_కీలకం_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_10 signing_కీలకం = { .దత్తాంశం = { 0U } };
  Eurydice_arr_02 verification_కీలకం = { .దత్తాంశం = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_generate_కీలకం_pair(randomness,
    &signing_కీలకం,
    &verification_కీలకం);
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_కీలకం_Pair){
        .signing_కీలకం = libcrux_ml_dsa_types_new_9b_ab(signing_కీలకం),
        .verification_కీలకం = libcrux_ml_dsa_types_new_7f_7d(verification_కీలకం)
      }
    );
}

/**
 Generate an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_48
libcrux_ml_dsa_ml_dsa_44_portable_sign(
  స్థిరరాశి Eurydice_arr_10 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign(libcrux_ml_dsa_types_as_ref_9b_ab(signing_కీలకం),
      సందేశం_2,
      context,
      randomness);
}

/**
 Generate an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_44_portable_sign_mut(
  స్థిరరాశి Eurydice_arr_10 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_mut(libcrux_ml_dsa_types_as_ref_9b_ab(signing_కీలకం),
      సందేశం_2,
      context,
      randomness,
      signature);
}

/**
 Generate a HashML-DSA-44 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_48
libcrux_ml_dsa_ml_dsa_44_portable_sign_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_10 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_బఫరు = { .దత్తాంశం = { 0U } };
  స్థిరరాశి Eurydice_arr_10 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_ab(signing_కీలకం);
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_pre_hashed_shake128(uu____0,
      సందేశం_2,
      context,
      Eurydice_array_గమ్యం_ముక్క_mut_01(&pre_hash_బఫరు),
      randomness);
}

/**
 Verify an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_44_portable_verify(
  స్థిరరాశి Eurydice_arr_02 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_85 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify(libcrux_ml_dsa_types_as_ref_7f_7d(verification_కీలకం),
      సందేశం_2,
      context,
      libcrux_ml_dsa_types_as_ref_c5_37(signature));
}

/**
 Verify a HashML-DSA-44 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_44_portable_verify_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_02 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_85 *signature
)
{
  Eurydice_arr_ec pre_hash_బఫరు = { .దత్తాంశం = { 0U } };
  స్థిరరాశి Eurydice_arr_02 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_7d(verification_కీలకం);
  Eurydice_borrow_ముక్క_u8 uu____1 = సందేశం_2;
  Eurydice_borrow_ముక్క_u8 uu____2 = context;
  Eurydice_mut_borrow_ముక్క_u8 uu____3 = Eurydice_array_గమ్యం_ముక్క_mut_01(&pre_hash_బఫరు);
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_37(signature));
}

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు libcrux_mldsa44_portable_H_DEFINED
#అయితే_ముగింపు /* libcrux_mldsa44_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa65_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే libcrux_mldsa65_portable_H
#నిర్వచించు libcrux_mldsa65_portable_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


/**
 Generate an ML-DSA-65 Key Pair
*/
స్థిర అంతఃవరుస libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_కీలకం_Pair
libcrux_ml_dsa_ml_dsa_65_portable_generate_కీలకం_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_24 signing_కీలకం = { .దత్తాంశం = { 0U } };
  Eurydice_arr_29 verification_కీలకం = { .దత్తాంశం = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_కీలకం_pair(randomness,
    &signing_కీలకం,
    &verification_కీలకం);
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_కీలకం_Pair){
        .signing_కీలకం = libcrux_ml_dsa_types_new_9b_e5(signing_కీలకం),
        .verification_కీలకం = libcrux_ml_dsa_types_new_7f_a2(verification_కీలకం)
      }
    );
}

/**
 Generate an ML-DSA-65 Key Pair
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_dsa_ml_dsa_65_portable_generate_కీలకం_pair_mut(
  Eurydice_arr_ec randomness,
  Eurydice_arr_24 *signing_కీలకం,
  Eurydice_arr_29 *verification_కీలకం
)
{
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_కీలకం_pair(randomness,
    signing_కీలకం,
    verification_కీలకం);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_8c
libcrux_ml_dsa_ml_dsa_65_portable_sign(
  స్థిరరాశి Eurydice_arr_24 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(libcrux_ml_dsa_types_as_ref_9b_e5(signing_కీలకం),
      సందేశం_2,
      context,
      randomness);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_65_portable_sign_mut(
  స్థిరరాశి Eurydice_arr_24 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(signing_కీలకం,
      సందేశం_2,
      context,
      randomness,
      signature);
}

/**
 Generate a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_8c
libcrux_ml_dsa_ml_dsa_65_portable_sign_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_24 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_బఫరు = { .దత్తాంశం = { 0U } };
  స్థిరరాశి Eurydice_arr_24 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_e5(signing_కీలకం);
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(uu____0,
      సందేశం_2,
      context,
      Eurydice_array_గమ్యం_ముక్క_mut_01(&pre_hash_బఫరు),
      randomness);
}

/**
 Verify an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_65_portable_verify(
  స్థిరరాశి Eurydice_arr_29 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_0c *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(libcrux_ml_dsa_types_as_ref_7f_a2(verification_కీలకం),
      సందేశం_2,
      context,
      libcrux_ml_dsa_types_as_ref_c5_5c(signature));
}

/**
 Verify a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_65_portable_verify_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_29 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_0c *signature
)
{
  Eurydice_arr_ec pre_hash_బఫరు = { .దత్తాంశం = { 0U } };
  స్థిరరాశి Eurydice_arr_29 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_a2(verification_కీలకం);
  Eurydice_borrow_ముక్క_u8 uu____1 = సందేశం_2;
  Eurydice_borrow_ముక్క_u8 uu____2 = context;
  Eurydice_mut_borrow_ముక్క_u8 uu____3 = Eurydice_array_గమ్యం_ముక్క_mut_01(&pre_hash_బఫరు);
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_5c(signature));
}

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు libcrux_mldsa65_portable_H_DEFINED
#అయితే_ముగింపు /* libcrux_mldsa65_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa87_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే libcrux_mldsa87_portable_H
#నిర్వచించు libcrux_mldsa87_portable_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


/**
 Generate an ML-DSA-87 Key Pair
*/
స్థిర అంతఃవరుస libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_కీలకం_Pair
libcrux_ml_dsa_ml_dsa_87_portable_generate_కీలకం_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_e2 signing_కీలకం = { .దత్తాంశం = { 0U } };
  Eurydice_arr_43 verification_కీలకం = { .దత్తాంశం = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_generate_కీలకం_pair(randomness,
    &signing_కీలకం,
    &verification_కీలకం);
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_కీలకం_Pair){
        .signing_కీలకం = libcrux_ml_dsa_types_new_9b_72(signing_కీలకం),
        .verification_కీలకం = libcrux_ml_dsa_types_new_7f_c6(verification_కీలకం)
      }
    );
}

/**
 Generate an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_8b
libcrux_ml_dsa_ml_dsa_87_portable_sign(
  స్థిరరాశి Eurydice_arr_e2 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign(libcrux_ml_dsa_types_as_ref_9b_72(signing_కీలకం),
      సందేశం_2,
      context,
      randomness);
}

/**
 Generate an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_53
libcrux_ml_dsa_ml_dsa_87_portable_sign_mut(
  స్థిరరాశి Eurydice_arr_e2 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_mut(libcrux_ml_dsa_types_as_ref_9b_72(signing_కీలకం),
      సందేశం_2,
      context,
      randomness,
      signature);
}

/**
 Generate a HashML-DSA-87 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_8b
libcrux_ml_dsa_ml_dsa_87_portable_sign_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_e2 *signing_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_బఫరు = { .దత్తాంశం = { 0U } };
  స్థిరరాశి Eurydice_arr_e2 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_72(signing_కీలకం);
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_pre_hashed_shake128(uu____0,
      సందేశం_2,
      context,
      Eurydice_array_గమ్యం_ముక్క_mut_01(&pre_hash_బఫరు),
      randomness);
}

/**
 Verify an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_87_portable_verify(
  స్థిరరాశి Eurydice_arr_43 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_93 *signature
)
{
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify(libcrux_ml_dsa_types_as_ref_7f_c6(verification_కీలకం),
      సందేశం_2,
      context,
      libcrux_ml_dsa_types_as_ref_c5_f1(signature));
}

/**
 Verify a HashML-DSA-87 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
స్థిర అంతఃవరుస core_ఫలితం_ఫలితం_41
libcrux_ml_dsa_ml_dsa_87_portable_verify_pre_hashed_shake128(
  స్థిరరాశి Eurydice_arr_43 *verification_కీలకం,
  Eurydice_borrow_ముక్క_u8 సందేశం_2,
  Eurydice_borrow_ముక్క_u8 context,
  స్థిరరాశి Eurydice_arr_93 *signature
)
{
  Eurydice_arr_ec pre_hash_బఫరు = { .దత్తాంశం = { 0U } };
  స్థిరరాశి Eurydice_arr_43 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_c6(verification_కీలకం);
  Eurydice_borrow_ముక్క_u8 uu____1 = సందేశం_2;
  Eurydice_borrow_ముక్క_u8 uu____2 = context;
  Eurydice_mut_borrow_ముక్క_u8 uu____3 = Eurydice_array_గమ్యం_ముక్క_mut_01(&pre_hash_బఫరు);
  తిరిగి
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_f1(signature));
}

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు libcrux_mldsa87_portable_H_DEFINED
#అయితే_ముగింపు /* libcrux_mldsa87_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mlkem768_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#నిర్వచితం_కాకపోతే libcrux_mlkem768_portable_H
#నిర్వచించు libcrux_mlkem768_portable_H



#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


స్థిర అంతఃవరుస Eurydice_arr_c7
libcrux_ml_kem_hash_functions_portable_G(Eurydice_borrow_ముక్క_u8 ఆదానం)
{
  Eurydice_arr_c7 digest = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_sha512(Eurydice_array_గమ్యం_ముక్క_mut_17(&digest), ఆదానం);
  తిరిగి digest;
}

స్థిర అంతఃవరుస Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_H(Eurydice_borrow_ముక్క_u8 ఆదానం)
{
  Eurydice_arr_ec digest = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_sha256(Eurydice_array_గమ్యం_ముక్క_mut_01(&digest), ఆదానం);
  తిరిగి digest;
}

#నిర్వచించు LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R ((KRML_CLITERAL(Eurydice_arr_34){ .దత్తాంశం = { -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468, 573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571, 1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275, -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097, 603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185, -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628 } }))

స్థిర KRML_MUSTINLINE int16_t libcrux_ml_kem_polynomial_zeta(కొలత_t i)
{
  తిరిగి LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R.దత్తాంశం[i];
}

#నిర్వచించు LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT ((కొలత_t)16U)

#నిర్వచించు LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ ((కొలత_t)16U)

#నిర్వచించు LIBCRUX_ML_KEM_సదిశ_TRAITS_MONTGOMERY_R_SQUARED_MOD_క్షేత్రం_MODULUS (1353)

#నిర్వచించు LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_MODULUS (3329)

#నిర్వచించు LIBCRUX_ML_KEM_సదిశ_TRAITS_INVERSE_యొక్క_MODULUS_MOD_MONTGOMERY_R (62209U)

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_సదిశ_type_from_i16_array(Eurydice_borrow_ముక్క_i16 array)
{
  Eurydice_arr_d6 arr;
  జ్ఞాపకం_నకలు(arr.దత్తాంశం,
    Eurydice_ముక్క_subslice_shared_a6(array,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)16U })).ptr,
    (కొలత_t)16U * పరిమాణం (int16_t));
  తిరిగి
    core_ఫలితం_unwrap_26_d3((
        KRML_CLITERAL(core_ఫలితం_ఫలితం_ec){ .ట్యాగ్ = core_ఫలితం_Ok, .val = { .case_Ok = arr } }
      ));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_from_i16_array_b8(Eurydice_borrow_ముక్క_i16 array)
{
  తిరిగి
    libcrux_ml_kem_సదిశ_portable_సదిశ_type_from_i16_array(libcrux_secrets_int_classify_ప్రజా_classify_ref_6d_39(array));
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6 libcrux_ml_kem_సదిశ_portable_సదిశ_type_zero(శూన్య)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_classify_27_4b((
        KRML_CLITERAL(Eurydice_arr_d6){ .దత్తాంశం = { 0U } }
      ));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6 libcrux_ml_kem_సదిశ_portable_ZERO_b8(శూన్య)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_సదిశ_type_zero();
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_arithmetic_కూడు(Eurydice_arr_d6 lhs, స్థిరరాశి Eurydice_arr_d6 *rhs)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    కొలత_t uu____0 = i0;
    lhs.దత్తాంశం[uu____0] += rhs->దత్తాంశం[i0];
  }
  తిరిగి lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_కూడు_b8(Eurydice_arr_d6 lhs, స్థిరరాశి Eurydice_arr_d6 *rhs)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_arithmetic_కూడు(lhs, rhs);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_arithmetic_sub(Eurydice_arr_d6 lhs, స్థిరరాశి Eurydice_arr_d6 *rhs)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    కొలత_t uu____0 = i0;
    lhs.దత్తాంశం[uu____0] -= rhs->దత్తాంశం[i0];
  }
  తిరిగి lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_sub_b8(Eurydice_arr_d6 lhs, స్థిరరాశి Eurydice_arr_d6 *rhs)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_arithmetic_sub(lhs, rhs);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_arithmetic_multiply_by_constant(Eurydice_arr_d6 vec, int16_t c)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    కొలత_t uu____0 = i0;
    vec.దత్తాంశం[uu____0] *= c;
  }
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_multiply_by_constant_b8(Eurydice_arr_d6 vec, int16_t c)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_arithmetic_multiply_by_constant(vec, c);
}

/**
 Note: This function is not secret independent
 Only use with public values.
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_arithmetic_cond_వ్యవకలనం_3329(Eurydice_arr_d6 vec)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    ఒకవేళ (libcrux_secrets_int_ప్రజా_integers_declassify_d8_39(vec.దత్తాంశం[i0]) >= 3329)
    {
      కొలత_t uu____0 = i0;
      vec.దత్తాంశం[uu____0] -= 3329;
    }
  }
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_cond_వ్యవకలనం_3329_b8(Eurydice_arr_d6 v)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_arithmetic_cond_వ్యవకలనం_3329(v);
}

#నిర్వచించు LIBCRUX_ML_KEM_సదిశ_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER (20159)

#నిర్వచించు LIBCRUX_ML_KEM_సదిశ_TRAITS_BARRETT_జరుపు (26)

#నిర్వచించు LIBCRUX_ML_KEM_సదిశ_TRAITS_BARRETT_R ((int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_KEM_సదిశ_TRAITS_BARRETT_జరుపు))

/**
 Signed Barrett Reduction

 Given an input `value`, `barrett_reduce` outputs a representative `result`
 such that:

 - result ≡ value (mod FIELD_MODULUS)
 - the absolute value of `result` is bound as follows:

 `|result| ≤ FIELD_MODULUS / 2 · (|value|/BARRETT_R + 1)

 Note: The input bound is 28296 to prevent overflow in the multiplication of quotient by FIELD_MODULUS

*/
స్థిర అంతఃవరుస int16_t
libcrux_ml_kem_సదిశ_portable_arithmetic_barrett_reduce_element(int16_t విలువ)
{
  int32_t
  t =
    libcrux_secrets_int_as_i32_f5(విలువ) *
      LIBCRUX_ML_KEM_సదిశ_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER
    + (LIBCRUX_ML_KEM_సదిశ_TRAITS_BARRETT_R >> 1U);
  int16_t
  quotient =
    libcrux_secrets_int_as_i16_36(t >> (uint32_t)LIBCRUX_ML_KEM_సదిశ_TRAITS_BARRETT_జరుపు);
  తిరిగి విలువ - quotient * LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_MODULUS;
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_arithmetic_barrett_reduce(Eurydice_arr_d6 vec)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    int16_t vi = libcrux_ml_kem_సదిశ_portable_arithmetic_barrett_reduce_element(vec.దత్తాంశం[i0]);
    vec.దత్తాంశం[i0] = vi;
  }
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_barrett_reduce_b8(Eurydice_arr_d6 సదిశ)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_arithmetic_barrett_reduce(సదిశ);
}

#నిర్వచించు LIBCRUX_ML_KEM_సదిశ_PORTABLE_ARITHMETIC_MONTGOMERY_జరుపు (16U)

/**
 Signed Montgomery Reduction

 Given an input `value`, `montgomery_reduce` outputs a representative `o`
 such that:

 - o ≡ value · MONTGOMERY_R^(-1) (mod FIELD_MODULUS)
 - the absolute value of `o` is bound as follows:

 `|result| ≤ ceil(|value| / MONTGOMERY_R) + 1665

 In particular, if `|value| ≤ FIELD_MODULUS-1 * FIELD_MODULUS-1`, then `|o| <= FIELD_MODULUS-1`.
 And, if `|value| ≤ pow2 16 * FIELD_MODULUS-1`, then `|o| <= FIELD_MODULUS + 1664

*/
స్థిర అంతఃవరుస int16_t
libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_reduce_element(int32_t విలువ)
{
  int32_t
  k =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(విలువ)) *
      libcrux_secrets_int_as_i32_b8(libcrux_secrets_int_ప్రజా_integers_classify_27_df(LIBCRUX_ML_KEM_సదిశ_TRAITS_INVERSE_యొక్క_MODULUS_MOD_MONTGOMERY_R));
  int32_t
  k_times_modulus =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(k)) *
      libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_ప్రజా_integers_classify_27_39(LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_MODULUS));
  int16_t
  c =
    libcrux_secrets_int_as_i16_36(k_times_modulus >>
        (uint32_t)LIBCRUX_ML_KEM_సదిశ_PORTABLE_ARITHMETIC_MONTGOMERY_జరుపు);
  int16_t
  విలువ_ఎగువ =
    libcrux_secrets_int_as_i16_36(విలువ >>
        (uint32_t)LIBCRUX_ML_KEM_సదిశ_PORTABLE_ARITHMETIC_MONTGOMERY_జరుపు);
  తిరిగి విలువ_ఎగువ - c;
}

/**
 If `fe` is some field element 'x' of the Kyber field and `fer` is congruent to
 `y · MONTGOMERY_R`, this procedure outputs a value that is congruent to
 `x · y`, as follows:

    `fe · fer ≡ x · y · MONTGOMERY_R (mod FIELD_MODULUS)`

 `montgomery_reduce` takes the value `x · y · MONTGOMERY_R` and outputs a representative
 `x · y · MONTGOMERY_R * MONTGOMERY_R^{-1} ≡ x · y (mod FIELD_MODULUS)`.
*/
స్థిర KRML_MUSTINLINE int16_t
libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_multiply_fe_by_fer(
  int16_t fe,
  int16_t fer
)
{
  int32_t లబ్ధం = libcrux_secrets_int_as_i32_f5(fe) * libcrux_secrets_int_as_i32_f5(fer);
  తిరిగి libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_reduce_element(లబ్ధం);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_d6 vec,
  int16_t c
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    vec.దత్తాంశం[i0] =
      libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_multiply_fe_by_fer(vec.దత్తాంశం[i0],
        c);
  }
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_montgomery_multiply_by_constant_b8(
  Eurydice_arr_d6 సదిశ,
  int16_t constant
)
{
  తిరిగి
    libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_multiply_by_constant(సదిశ,
      libcrux_secrets_int_ప్రజా_integers_classify_27_39(constant));
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_arithmetic_bitwise_and_with_constant(
  Eurydice_arr_d6 vec,
  int16_t c
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    కొలత_t uu____0 = i0;
    vec.దత్తాంశం[uu____0] &= c;
  }
  తిరిగి vec;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.arithmetic.shift_right
with const generics
- SHIFT_BY= 15
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_arithmetic_జరుపు_కుడి_ef(Eurydice_arr_d6 vec)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    vec.దత్తాంశం[i0] >>= (uint32_t)15;
  }
  తిరిగి vec;
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_arithmetic_గమ్యం_unsigned_representative(Eurydice_arr_d6 a)
{
  Eurydice_arr_d6 t = libcrux_ml_kem_సదిశ_portable_arithmetic_జరుపు_కుడి_ef(a);
  Eurydice_arr_d6
  fm =
    libcrux_ml_kem_సదిశ_portable_arithmetic_bitwise_and_with_constant(t,
      LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_MODULUS);
  తిరిగి libcrux_ml_kem_సదిశ_portable_arithmetic_కూడు(a, &fm);
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_గమ్యం_unsigned_representative_b8(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_arithmetic_గమ్యం_unsigned_representative(a);
}

/**
 The `compress_*` functions implement the `Compress` function specified in the NIST FIPS
 203 standard (Page 18, Expression 4.5), which is defined as:

 ```plaintext
 Compress_d: ℤq -> ℤ_{2ᵈ}
 Compress_d(x) = ⌈(2ᵈ/q)·x⌋
 ```

 Since `⌈x⌋ = ⌊x + 1/2⌋` we have:

 ```plaintext
 Compress_d(x) = ⌊(2ᵈ/q)·x + 1/2⌋
               = ⌊(2^{d+1}·x + q) / 2q⌋
 ```

 For further information about the function implementations, consult the
 `implementation_notes.pdf` document in this directory.

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
స్థిర అంతఃవరుస uint8_t
libcrux_ml_kem_సదిశ_portable_compress_compress_సందేశం_coefficient(uint16_t fe)
{
  int16_t
  shifted =
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(1664) - libcrux_secrets_int_as_i16_ca(fe);
  int16_t ముసుగు = shifted >> 15U;
  int16_t shifted_గమ్యం_ధనాత్మక = ముసుగు ^ shifted;
  int16_t shifted_ధనాత్మక_లోపల_range = shifted_గమ్యం_ధనాత్మక - 832;
  int16_t r0 = shifted_ధనాత్మక_లోపల_range >> 15U;
  int16_t r1 = r0 & 1;
  తిరిగి libcrux_secrets_int_as_u8_f5(r1);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_compress_compress_1(Eurydice_arr_d6 a)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    a.దత్తాంశం[i0] =
      libcrux_secrets_int_as_i16_59(libcrux_ml_kem_సదిశ_portable_compress_compress_సందేశం_coefficient(libcrux_secrets_int_as_u16_f5(a.దత్తాంశం[i0])));
  }
  తిరిగి a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6 libcrux_ml_kem_సదిశ_portable_compress_1_b8(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_compress_compress_1(a);
}

స్థిర KRML_MUSTINLINE uint32_t
libcrux_ml_kem_సదిశ_portable_arithmetic_get_n_కనిష్ఠ_significant_బిట్లు(
  uint8_t n,
  uint32_t విలువ
)
{
  తిరిగి విలువ & ((1U << (uint32_t)n) - 1U);
}

స్థిర అంతఃవరుస int16_t
libcrux_ml_kem_సదిశ_portable_compress_compress_ciphertext_coefficient(
  uint8_t coefficient_బిట్లు,
  uint16_t fe
)
{
  uint64_t compressed = libcrux_secrets_int_as_u64_ca(fe) << (uint32_t)coefficient_బిట్లు;
  compressed += 1664ULL;
  compressed *= 10321340ULL;
  compressed >>= 35U;
  తిరిగి
    libcrux_secrets_int_as_i16_b8(libcrux_ml_kem_సదిశ_portable_arithmetic_get_n_కనిష్ఠ_significant_బిట్లు(coefficient_బిట్లు,
        libcrux_secrets_int_as_u32_a3(compressed)));
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_compress_decompress_1(Eurydice_arr_d6 a)
{
  Eurydice_arr_d6 z = libcrux_ml_kem_సదిశ_portable_సదిశ_type_zero();
  Eurydice_arr_d6 s = libcrux_ml_kem_సదిశ_portable_arithmetic_sub(z, &a);
  Eurydice_arr_d6
  res = libcrux_ml_kem_సదిశ_portable_arithmetic_bitwise_and_with_constant(s, 1665);
  తిరిగి res;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6 libcrux_ml_kem_సదిశ_portable_decompress_1_b8(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_compress_decompress_1(a);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(
  Eurydice_arr_d6 *vec,
  int16_t zeta,
  కొలత_t i,
  కొలత_t j
)
{
  int16_t
  t =
    libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_multiply_fe_by_fer(vec->దత్తాంశం[j],
      libcrux_secrets_int_ప్రజా_integers_classify_27_39(zeta));
  int16_t a_minus_t = vec->దత్తాంశం[i] - t;
  int16_t a_plus_t = vec->దత్తాంశం[i] + t;
  vec->దత్తాంశం[j] = a_minus_t;
  vec->దత్తాంశం[i] = a_plus_t;
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_ntt_layer_1_అడుగు(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta0, (కొలత_t)0U, (కొలత_t)2U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta0, (కొలత_t)1U, (కొలత_t)3U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta1, (కొలత_t)4U, (కొలత_t)6U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta1, (కొలత_t)5U, (కొలత_t)7U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta2, (కొలత_t)8U, (కొలత_t)10U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta2, (కొలత_t)9U, (కొలత_t)11U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta3, (కొలత_t)12U, (కొలత_t)14U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta3, (కొలత_t)13U, (కొలత_t)15U);
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_layer_1_అడుగు_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_ntt_ntt_layer_1_అడుగు(a, zeta0, zeta1, zeta2, zeta3);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_ntt_layer_2_అడుగు(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta0, (కొలత_t)0U, (కొలత_t)4U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta0, (కొలత_t)1U, (కొలత_t)5U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta0, (కొలత_t)2U, (కొలత_t)6U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta0, (కొలత_t)3U, (కొలత_t)7U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta1, (కొలత_t)8U, (కొలత_t)12U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta1, (కొలత_t)9U, (కొలత_t)13U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta1, (కొలత_t)10U, (కొలత_t)14U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta1, (కొలత_t)11U, (కొలత_t)15U);
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_layer_2_అడుగు_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_ntt_ntt_layer_2_అడుగు(a, zeta0, zeta1);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_ntt_layer_3_అడుగు(Eurydice_arr_d6 vec, int16_t zeta)
{
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta, (కొలత_t)0U, (కొలత_t)8U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta, (కొలత_t)1U, (కొలత_t)9U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta, (కొలత_t)2U, (కొలత_t)10U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta, (కొలత_t)3U, (కొలత_t)11U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta, (కొలత_t)4U, (కొలత_t)12U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta, (కొలత_t)5U, (కొలత_t)13U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta, (కొలత_t)6U, (కొలత_t)14U);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_అడుగు(&vec, zeta, (కొలత_t)7U, (కొలత_t)15U);
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_layer_3_అడుగు_b8(Eurydice_arr_d6 a, int16_t zeta)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_ntt_ntt_layer_3_అడుగు(a, zeta);
}

స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(
  Eurydice_arr_d6 *vec,
  int16_t zeta,
  కొలత_t i,
  కొలత_t j
)
{
  int16_t a_minus_b = vec->దత్తాంశం[j] - vec->దత్తాంశం[i];
  int16_t a_plus_b = vec->దత్తాంశం[j] + vec->దత్తాంశం[i];
  int16_t o0 = libcrux_ml_kem_సదిశ_portable_arithmetic_barrett_reduce_element(a_plus_b);
  int16_t
  o1 =
    libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      libcrux_secrets_int_ప్రజా_integers_classify_27_39(zeta));
  vec->దత్తాంశం[i] = o0;
  vec->దత్తాంశం[j] = o1;
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_layer_1_అడుగు(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta0, (కొలత_t)0U, (కొలత_t)2U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta0, (కొలత_t)1U, (కొలత_t)3U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta1, (కొలత_t)4U, (కొలత_t)6U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta1, (కొలత_t)5U, (కొలత_t)7U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta2, (కొలత_t)8U, (కొలత_t)10U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta2, (కొలత_t)9U, (కొలత_t)11U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta3, (కొలత_t)12U, (కొలత_t)14U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta3, (కొలత_t)13U, (కొలత_t)15U);
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_inv_ntt_layer_1_అడుగు_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_layer_1_అడుగు(a, zeta0, zeta1, zeta2, zeta3);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_layer_2_అడుగు(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta0, (కొలత_t)0U, (కొలత_t)4U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta0, (కొలత_t)1U, (కొలత_t)5U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta0, (కొలత_t)2U, (కొలత_t)6U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta0, (కొలత_t)3U, (కొలత_t)7U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta1, (కొలత_t)8U, (కొలత_t)12U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta1, (కొలత_t)9U, (కొలత_t)13U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta1, (కొలత_t)10U, (కొలత_t)14U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta1, (కొలత_t)11U, (కొలత_t)15U);
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_inv_ntt_layer_2_అడుగు_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_layer_2_అడుగు(a, zeta0, zeta1);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_layer_3_అడుగు(Eurydice_arr_d6 vec, int16_t zeta)
{
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta, (కొలత_t)0U, (కొలత_t)8U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta, (కొలత_t)1U, (కొలత_t)9U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta, (కొలత_t)2U, (కొలత_t)10U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta, (కొలత_t)3U, (కొలత_t)11U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta, (కొలత_t)4U, (కొలత_t)12U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta, (కొలత_t)5U, (కొలత_t)13U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta, (కొలత_t)6U, (కొలత_t)14U);
  libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_అడుగు(&vec, zeta, (కొలత_t)7U, (కొలత_t)15U);
  తిరిగి vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_inv_ntt_layer_3_అడుగు_b8(Eurydice_arr_d6 a, int16_t zeta)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_ntt_inv_ntt_layer_3_అడుగు(a, zeta);
}

/**
 Compute the product of two Kyber binomials with respect to the
 modulus `X² - zeta`.

 This function almost implements <strong>Algorithm 11</strong> of the
 NIST FIPS 203 standard, which is reproduced below:

 ```plaintext
 Input:  a₀, a₁, b₀, b₁ ∈ ℤq.
 Input: γ ∈ ℤq.
 Output: c₀, c₁ ∈ ℤq.

 c₀ ← a₀·b₀ + a₁·b₁·γ
 c₁ ← a₀·b₁ + a₁·b₀
 return c₀, c₁
 ```
 We say "almost" because the coefficients output by this function are in
 the Montgomery domain (unlike in the specification).

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply_binomials(
  స్థిరరాశి Eurydice_arr_d6 *a,
  స్థిరరాశి Eurydice_arr_d6 *b,
  int16_t zeta,
  కొలత_t i,
  Eurydice_arr_d6 *బహిర్గతం
)
{
  int16_t ai = a->దత్తాంశం[(కొలత_t)2U * i];
  int16_t bi = b->దత్తాంశం[(కొలత_t)2U * i];
  int16_t aj = a->దత్తాంశం[(కొలత_t)2U * i + (కొలత_t)1U];
  int16_t bj = b->దత్తాంశం[(కొలత_t)2U * i + (కొలత_t)1U];
  int32_t ai_bi = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t aj_bj_ = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bj);
  int16_t aj_bj = libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_reduce_element(aj_bj_);
  int32_t
  aj_bj_zeta = libcrux_secrets_int_as_i32_f5(aj_bj) * libcrux_secrets_int_as_i32_f5(zeta);
  int32_t ai_bi_aj_bj = ai_bi + aj_bj_zeta;
  int16_t o0 = libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_reduce_element(ai_bi_aj_bj);
  int32_t ai_bj = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bj);
  int32_t aj_bi = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t ai_bj_aj_bi = ai_bj + aj_bi;
  int16_t o1 = libcrux_ml_kem_సదిశ_portable_arithmetic_montgomery_reduce_element(ai_bj_aj_bi);
  బహిర్గతం->దత్తాంశం[(కొలత_t)2U * i] = o0;
  బహిర్గతం->దత్తాంశం[(కొలత_t)2U * i + (కొలత_t)1U] = o1;
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply(
  స్థిరరాశి Eurydice_arr_d6 *lhs,
  స్థిరరాశి Eurydice_arr_d6 *rhs,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  int16_t nzeta0 = -zeta0;
  int16_t nzeta1 = -zeta1;
  int16_t nzeta2 = -zeta2;
  int16_t nzeta3 = -zeta3;
  Eurydice_arr_d6 బహిర్గతం = libcrux_ml_kem_సదిశ_portable_సదిశ_type_zero();
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(zeta0),
    (కొలత_t)0U,
    &బహిర్గతం);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(nzeta0),
    (కొలత_t)1U,
    &బహిర్గతం);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(zeta1),
    (కొలత_t)2U,
    &బహిర్గతం);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(nzeta1),
    (కొలత_t)3U,
    &బహిర్గతం);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(zeta2),
    (కొలత_t)4U,
    &బహిర్గతం);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(nzeta2),
    (కొలత_t)5U,
    &బహిర్గతం);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(zeta3),
    (కొలత_t)6U,
    &బహిర్గతం);
  libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ప్రజా_integers_classify_27_39(nzeta3),
    (కొలత_t)7U,
    &బహిర్గతం);
  తిరిగి బహిర్గతం;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_ntt_multiply_b8(
  స్థిరరాశి Eurydice_arr_d6 *lhs,
  స్థిరరాశి Eurydice_arr_d6 *rhs,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_ntt_ntt_multiply(lhs, rhs, zeta0, zeta1, zeta2, zeta3);
}

స్థిర KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_ml_kem_సదిశ_portable_serialize_serialize_1(Eurydice_arr_d6 v)
{
  uint8_t
  result0 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[0U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[1U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[2U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[3U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[4U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[5U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[6U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[7U]) << 7U;
  uint8_t
  result1 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[8U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[9U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[10U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[11U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[12U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[13U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[14U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.దత్తాంశం[15U]) << 7U;
  తిరిగి (KRML_CLITERAL(Eurydice_array_u8x2){ .దత్తాంశం = { result0, result1 } });
}

స్థిర అంతఃవరుస Eurydice_array_u8x2 libcrux_ml_kem_సదిశ_portable_serialize_1(Eurydice_arr_d6 a)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_declassify_d8_75(libcrux_ml_kem_సదిశ_portable_serialize_serialize_1(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_array_u8x2
libcrux_ml_kem_సదిశ_portable_serialize_1_b8(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_serialize_1(a);
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_serialize_deserialize_1(Eurydice_borrow_ముక్క_u8 v)
{
  int16_t result0 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] & 1U);
  int16_t result1 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 1U & 1U);
  int16_t result2 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 2U & 1U);
  int16_t result3 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 3U & 1U);
  int16_t result4 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 4U & 1U);
  int16_t result5 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 5U & 1U);
  int16_t result6 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 6U & 1U);
  int16_t result7 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 7U & 1U);
  int16_t result8 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] & 1U);
  int16_t result9 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 1U & 1U);
  int16_t result10 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 2U & 1U);
  int16_t result11 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 3U & 1U);
  int16_t result12 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 4U & 1U);
  int16_t result13 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 5U & 1U);
  int16_t result14 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 6U & 1U);
  int16_t result15 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 7U & 1U);
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .దత్తాంశం = {
          result0, result1, result2, result3, result4, result5, result6, result7, result8, result9,
          result10, result11, result12, result13, result14, result15
        }
      }
    );
}

స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_deserialize_1(Eurydice_borrow_ముక్క_u8 a)
{
  తిరిగి
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_1(libcrux_secrets_int_classify_ప్రజా_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_deserialize_1_b8(Eurydice_borrow_ముక్క_u8 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_deserialize_1(a);
}

స్థిర KRML_MUSTINLINE uint8_t_x4
libcrux_ml_kem_సదిశ_portable_serialize_serialize_4_int(Eurydice_borrow_ముక్క_i16 v)
{
  uint8_t
  result0 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[1U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[0U]);
  uint8_t
  result1 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[3U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[2U]);
  uint8_t
  result2 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[5U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[4U]);
  uint8_t
  result3 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[7U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[6U]);
  తిరిగి
    (KRML_CLITERAL(uint8_t_x4){ .fst = result0, .snd = result1, .thd = result2, .f3 = result3 });
}

స్థిర KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_ml_kem_సదిశ_portable_serialize_serialize_4(Eurydice_arr_d6 v)
{
  uint8_t_x4
  result0_3 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_4_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)8U })));
  uint8_t_x4
  result4_7 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_4_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)8U, .చివర = (కొలత_t)16U })));
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_array_u8x8){
        .దత్తాంశం = {
          result0_3.fst, result0_3.snd, result0_3.thd, result0_3.f3, result4_7.fst, result4_7.snd,
          result4_7.thd, result4_7.f3
        }
      }
    );
}

స్థిర అంతఃవరుస Eurydice_array_u8x8 libcrux_ml_kem_సదిశ_portable_serialize_4(Eurydice_arr_d6 a)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_declassify_d8_52(libcrux_ml_kem_సదిశ_portable_serialize_serialize_4(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_array_u8x8
libcrux_ml_kem_సదిశ_portable_serialize_4_b8(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_serialize_4(a);
}

స్థిర KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_సదిశ_portable_serialize_deserialize_4_int(Eurydice_borrow_ముక్క_u8 బైట్లు)
{
  int16_t v0 = libcrux_secrets_int_as_i16_59((uint32_t)బైట్లు.ptr[0U] & 15U);
  int16_t v1 = libcrux_secrets_int_as_i16_59((uint32_t)బైట్లు.ptr[0U] >> 4U & 15U);
  int16_t v2 = libcrux_secrets_int_as_i16_59((uint32_t)బైట్లు.ptr[1U] & 15U);
  int16_t v3 = libcrux_secrets_int_as_i16_59((uint32_t)బైట్లు.ptr[1U] >> 4U & 15U);
  int16_t v4 = libcrux_secrets_int_as_i16_59((uint32_t)బైట్లు.ptr[2U] & 15U);
  int16_t v5 = libcrux_secrets_int_as_i16_59((uint32_t)బైట్లు.ptr[2U] >> 4U & 15U);
  int16_t v6 = libcrux_secrets_int_as_i16_59((uint32_t)బైట్లు.ptr[3U] & 15U);
  int16_t v7 = libcrux_secrets_int_as_i16_59((uint32_t)బైట్లు.ptr[3U] >> 4U & 15U);
  తిరిగి
    (
      KRML_CLITERAL(int16_t_x8){
        .fst = v0,
        .snd = v1,
        .thd = v2,
        .f3 = v3,
        .f4 = v4,
        .f5 = v5,
        .f6 = v6,
        .f7 = v7
      }
    );
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_serialize_deserialize_4(Eurydice_borrow_ముక్క_u8 బైట్లు)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_4_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)4U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_4_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)4U, .చివర = (కొలత_t)8U })));
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .దత్తాంశం = {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_deserialize_4(Eurydice_borrow_ముక్క_u8 a)
{
  తిరిగి
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_4(libcrux_secrets_int_classify_ప్రజా_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_deserialize_4_b8(Eurydice_borrow_ముక్క_u8 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_deserialize_4(a);
}

స్థిర KRML_MUSTINLINE uint8_t_x5
libcrux_ml_kem_సదిశ_portable_serialize_serialize_10_int(Eurydice_borrow_ముక్క_i16 v)
{
  uint8_t r0 = libcrux_secrets_int_as_u8_f5(v.ptr[0U] & 255);
  uint8_t
  r1 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[1U] & 63) << 2U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[0U] >> 8U & 3);
  uint8_t
  r2 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[2U] & 15) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[1U] >> 6U & 15);
  uint8_t
  r3 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[3U] & 3) << 6U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[2U] >> 4U & 63);
  uint8_t r4 = libcrux_secrets_int_as_u8_f5(v.ptr[3U] >> 2U & 255);
  తిరిగి (KRML_CLITERAL(uint8_t_x5){ .fst = r0, .snd = r1, .thd = r2, .f3 = r3, .f4 = r4 });
}

స్థిర KRML_MUSTINLINE Eurydice_arr_fc
libcrux_ml_kem_సదిశ_portable_serialize_serialize_10(Eurydice_arr_d6 v)
{
  uint8_t_x5
  r0_4 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_10_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)4U })));
  uint8_t_x5
  r5_9 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_10_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)4U, .చివర = (కొలత_t)8U })));
  uint8_t_x5
  r10_14 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_10_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)8U, .చివర = (కొలత_t)12U })));
  uint8_t_x5
  r15_19 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_10_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)12U, .చివర = (కొలత_t)16U })));
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_arr_fc){
        .దత్తాంశం = {
          r0_4.fst, r0_4.snd, r0_4.thd, r0_4.f3, r0_4.f4, r5_9.fst, r5_9.snd, r5_9.thd, r5_9.f3,
          r5_9.f4, r10_14.fst, r10_14.snd, r10_14.thd, r10_14.f3, r10_14.f4, r15_19.fst, r15_19.snd,
          r15_19.thd, r15_19.f3, r15_19.f4
        }
      }
    );
}

స్థిర అంతఃవరుస Eurydice_arr_fc libcrux_ml_kem_సదిశ_portable_serialize_10(Eurydice_arr_d6 a)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_declassify_d8_2b(libcrux_ml_kem_సదిశ_portable_serialize_serialize_10(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_fc libcrux_ml_kem_సదిశ_portable_serialize_10_b8(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_serialize_10(a);
}

స్థిర KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_సదిశ_portable_serialize_deserialize_10_int(Eurydice_borrow_ముక్క_u8 బైట్లు)
{
  int16_t
  r0 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(బైట్లు.ptr[1U])
      & 3)
      << 8U)
      | (libcrux_secrets_int_as_i16_59(బైట్లు.ptr[0U]) & 255));
  int16_t
  r1 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(బైట్లు.ptr[2U])
      & 15)
      << 6U)
      | libcrux_secrets_int_as_i16_59(బైట్లు.ptr[1U]) >> 2U);
  int16_t
  r2 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(బైట్లు.ptr[3U])
      & 63)
      << 4U)
      | libcrux_secrets_int_as_i16_59(బైట్లు.ptr[2U]) >> 4U);
  int16_t
  r3 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)libcrux_secrets_int_as_i16_59(బైట్లు.ptr[4U])
      << 2U)
      | libcrux_secrets_int_as_i16_59(బైట్లు.ptr[3U]) >> 6U);
  int16_t
  r4 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(బైట్లు.ptr[6U])
      & 3)
      << 8U)
      | (libcrux_secrets_int_as_i16_59(బైట్లు.ptr[5U]) & 255));
  int16_t
  r5 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(బైట్లు.ptr[7U])
      & 15)
      << 6U)
      | libcrux_secrets_int_as_i16_59(బైట్లు.ptr[6U]) >> 2U);
  int16_t
  r6 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(బైట్లు.ptr[8U])
      & 63)
      << 4U)
      | libcrux_secrets_int_as_i16_59(బైట్లు.ptr[7U]) >> 4U);
  int16_t
  r7 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)libcrux_secrets_int_as_i16_59(బైట్లు.ptr[9U])
      << 2U)
      | libcrux_secrets_int_as_i16_59(బైట్లు.ptr[8U]) >> 6U);
  తిరిగి
    (
      KRML_CLITERAL(int16_t_x8){
        .fst = r0,
        .snd = r1,
        .thd = r2,
        .f3 = r3,
        .f4 = r4,
        .f5 = r5,
        .f6 = r6,
        .f7 = r7
      }
    );
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_serialize_deserialize_10(Eurydice_borrow_ముక్క_u8 బైట్లు)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_10_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)10U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_10_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)10U, .చివర = (కొలత_t)20U })));
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .దత్తాంశం = {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_deserialize_10(Eurydice_borrow_ముక్క_u8 a)
{
  తిరిగి
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_10(libcrux_secrets_int_classify_ప్రజా_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_deserialize_10_b8(Eurydice_borrow_ముక్క_u8 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_deserialize_10(a);
}

స్థిర KRML_MUSTINLINE uint8_t_x3
libcrux_ml_kem_సదిశ_portable_serialize_serialize_12_int(Eurydice_borrow_ముక్క_i16 v)
{
  uint8_t r0 = libcrux_secrets_int_as_u8_f5(v.ptr[0U] & 255);
  uint8_t
  r1 =
    libcrux_secrets_int_as_u8_f5(v.ptr[0U] >> 8U | (int16_t)((uint32_t)(v.ptr[1U] & 15) << 4U));
  uint8_t r2 = libcrux_secrets_int_as_u8_f5(v.ptr[1U] >> 4U & 255);
  తిరిగి (KRML_CLITERAL(uint8_t_x3){ .fst = r0, .snd = r1, .thd = r2 });
}

స్థిర KRML_MUSTINLINE Eurydice_arr_94
libcrux_ml_kem_సదిశ_portable_serialize_serialize_12(Eurydice_arr_d6 v)
{
  uint8_t_x3
  r0_2 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_12_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)2U })));
  uint8_t_x3
  r3_5 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_12_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)2U, .చివర = (కొలత_t)4U })));
  uint8_t_x3
  r6_8 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_12_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)4U, .చివర = (కొలత_t)6U })));
  uint8_t_x3
  r9_11 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_12_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)6U, .చివర = (కొలత_t)8U })));
  uint8_t_x3
  r12_14 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_12_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)8U, .చివర = (కొలత_t)10U })));
  uint8_t_x3
  r15_17 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_12_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)10U, .చివర = (కొలత_t)12U })));
  uint8_t_x3
  r18_20 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_12_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)12U, .చివర = (కొలత_t)14U })));
  uint8_t_x3
  r21_23 =
    libcrux_ml_kem_సదిశ_portable_serialize_serialize_12_int(Eurydice_array_గమ్యం_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)14U, .చివర = (కొలత_t)16U })));
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_arr_94){
        .దత్తాంశం = {
          r0_2.fst, r0_2.snd, r0_2.thd, r3_5.fst, r3_5.snd, r3_5.thd, r6_8.fst, r6_8.snd, r6_8.thd,
          r9_11.fst, r9_11.snd, r9_11.thd, r12_14.fst, r12_14.snd, r12_14.thd, r15_17.fst,
          r15_17.snd, r15_17.thd, r18_20.fst, r18_20.snd, r18_20.thd, r21_23.fst, r21_23.snd,
          r21_23.thd
        }
      }
    );
}

స్థిర అంతఃవరుస Eurydice_arr_94 libcrux_ml_kem_సదిశ_portable_serialize_12(Eurydice_arr_d6 a)
{
  తిరిగి
    libcrux_secrets_int_ప్రజా_integers_declassify_d8_40(libcrux_ml_kem_సదిశ_portable_serialize_serialize_12(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_94 libcrux_ml_kem_సదిశ_portable_serialize_12_b8(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_serialize_12(a);
}

స్థిర KRML_MUSTINLINE int16_t_x2
libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12_int(Eurydice_borrow_ముక్క_u8 బైట్లు)
{
  int16_t byte0 = libcrux_secrets_int_as_i16_59(బైట్లు.ptr[0U]);
  int16_t byte1 = libcrux_secrets_int_as_i16_59(బైట్లు.ptr[1U]);
  int16_t byte2 = libcrux_secrets_int_as_i16_59(బైట్లు.ptr[2U]);
  int16_t r0 = (int16_t)((uint32_t)(byte1 & 15) << 8U) | (byte0 & 255);
  int16_t r1 = (int16_t)((uint32_t)byte2 << 4U) | (byte1 >> 4U & 15);
  తిరిగి (KRML_CLITERAL(int16_t_x2){ .fst = r0, .snd = r1 });
}

స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12(Eurydice_borrow_ముక్క_u8 బైట్లు)
{
  int16_t_x2
  v0_1 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)3U })));
  int16_t_x2
  v2_3 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)3U, .చివర = (కొలత_t)6U })));
  int16_t_x2
  v4_5 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)6U, .చివర = (కొలత_t)9U })));
  int16_t_x2
  v6_7 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)9U, .చివర = (కొలత_t)12U })));
  int16_t_x2
  v8_9 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)12U, .చివర = (కొలత_t)15U })));
  int16_t_x2
  v10_11 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)15U, .చివర = (కొలత_t)18U })));
  int16_t_x2
  v12_13 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)18U, .చివర = (కొలత_t)21U })));
  int16_t_x2
  v14_15 =
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12_int(Eurydice_ముక్క_subslice_shared_c8(బైట్లు,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)21U, .చివర = (కొలత_t)24U })));
  తిరిగి
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .దత్తాంశం = {
          v0_1.fst, v0_1.snd, v2_3.fst, v2_3.snd, v4_5.fst, v4_5.snd, v6_7.fst, v6_7.snd, v8_9.fst,
          v8_9.snd, v10_11.fst, v10_11.snd, v12_13.fst, v12_13.snd, v14_15.fst, v14_15.snd
        }
      }
    );
}

స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_deserialize_12(Eurydice_borrow_ముక్క_u8 a)
{
  తిరిగి
    libcrux_ml_kem_సదిశ_portable_serialize_deserialize_12(libcrux_secrets_int_classify_ప్రజా_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_deserialize_12_b8(Eurydice_borrow_ముక్క_u8 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_deserialize_12(a);
}

స్థిర KRML_MUSTINLINE కొలత_t
libcrux_ml_kem_సదిశ_portable_sampling_rej_sample(
  Eurydice_borrow_ముక్క_u8 a,
  Eurydice_mut_borrow_ముక్క_i16 ఫలితం
)
{
  కొలత_t sampled = (కొలత_t)0U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < a.meta / (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    int16_t b1 = (int16_t)(uint32_t)a.ptr[i0 * (కొలత_t)3U + (కొలత_t)0U];
    int16_t b2 = (int16_t)(uint32_t)a.ptr[i0 * (కొలత_t)3U + (కొలత_t)1U];
    int16_t b3 = (int16_t)(uint32_t)a.ptr[i0 * (కొలత_t)3U + (కొలత_t)2U];
    int16_t d1 = (int16_t)((uint32_t)(b2 & 15) << 8U) | b1;
    int16_t d2 = (int16_t)((uint32_t)b3 << 4U) | b2 >> 4U;
    ఒకవేళ (d1 < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_MODULUS)
    {
      ఒకవేళ (sampled < (కొలత_t)16U)
      {
        ఫలితం.ptr[sampled] = d1;
        sampled++;
      }
    }
    ఒకవేళ (d2 < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_MODULUS)
    {
      ఒకవేళ (sampled < (కొలత_t)16U)
      {
        ఫలితం.ptr[sampled] = d2;
        sampled++;
      }
    }
  }
  తిరిగి sampled;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
స్థిర అంతఃవరుస కొలత_t
libcrux_ml_kem_సదిశ_portable_rej_sample_b8(
  Eurydice_borrow_ముక్క_u8 a,
  Eurydice_mut_borrow_ముక్క_i16 బహిర్గతం
)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_sampling_rej_sample(a, బహిర్గతం);
}

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_సదిశ_U_COMPRESSION_గుణకం ((కొలత_t)10U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_C1_ఖండం_కొలత (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_సదిశ_U_COMPRESSION_గుణకం / (కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_RANK ((కొలత_t)3U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_C1_కొలత (LIBCRUX_ML_KEM_MLKEM768_C1_ఖండం_కొలత * LIBCRUX_ML_KEM_MLKEM768_RANK)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_సదిశ_V_COMPRESSION_గుణకం ((కొలత_t)4U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_C2_కొలత (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_సదిశ_V_COMPRESSION_గుణకం / (కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_కొలత (LIBCRUX_ML_KEM_MLKEM768_C1_కొలత + LIBCRUX_ML_KEM_MLKEM768_C2_కొలత)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_కొలత (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_బిట్లు_చొప్పున_COEFFICIENT / (కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_ప్రజా_కీలకం_కొలత (LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_కొలత + (కొలత_t)32U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_కీలకం_కొలత (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_బిట్లు_చొప్పున_COEFFICIENT / (కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_ETA1 ((కొలత_t)2U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_ETA1_RANDOMNESS_కొలత (LIBCRUX_ML_KEM_MLKEM768_ETA1 * (కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_ETA2 ((కొలత_t)2U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_ETA2_RANDOMNESS_కొలత (LIBCRUX_ML_KEM_MLKEM768_ETA2 * (కొలత_t)64U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_IMPLICIT_REJECTION_HASH_ఆదానం_కొలత (LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_కొలత)

రకనిర్వచనం Eurydice_arr_7d libcrux_ml_kem_mlkem768_Ml_Kem768_వ్యక్తిగత_కీలకం;

రకనిర్వచనం Eurydice_arr_5f libcrux_ml_kem_mlkem768_Ml_Kem768_ప్రజా_కీలకం;

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_RANKED_బైట్లు_చొప్పున_RING_ELEMENT (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_బిట్లు_చొప్పున_RING_ELEMENT / (కొలత_t)8U)

#నిర్వచించు LIBCRUX_ML_KEM_MLKEM768_SECRET_కీలకం_కొలత (LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_కీలకం_కొలత + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_ప్రజా_కీలకం_కొలత + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_కొలత + LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత)

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $16size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_9e_s { Eurydice_arr_d6 దత్తాంశం[16U]; } Eurydice_arr_9e;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_polynomial_PolynomialRingElement_1d
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_bb0_s { Eurydice_arr_9e దత్తాంశం[3U]; } Eurydice_arr_bb0;

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర అంతఃవరుస Eurydice_arr_9e libcrux_ml_kem_polynomial_ZERO_d6_ea(శూన్య)
{
  Eurydice_arr_9e lit;
  Eurydice_arr_d6 repeat_వ్యక్తీకరణ[16U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_ml_kem_సదిశ_portable_ZERO_b8();
  }
  జ్ఞాపకం_నకలు(lit.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)16U * పరిమాణం (Eurydice_arr_d6));
  తిరిగి lit;
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::ind_cpa::decrypt::closure<Vector, K, CIPHERTEXT_SIZE, VECTOR_U_ENCODED_SIZE, U_COMPRESSION_FACTOR, V_COMPRESSION_FACTOR>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.decrypt.call_mut_0b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- VECTOR_U_ENCODED_SIZE= 960
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_01(శూన్య **_, కొలత_t tupled_వాదనలు)
{
  తిరిగి libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_to_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_గమ్యం_uncompressed_ring_element_ea(
  Eurydice_borrow_ముక్క_u8 serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  కొరకు (కొలత_t i = (కొలత_t)0U; i < serialized.meta / (కొలత_t)24U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)24U,
            .చివర = i0 * (కొలత_t)24U + (కొలత_t)24U
          }
        ));
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_సదిశ_portable_deserialize_12_b8(బైట్లు);
    re.దత్తాంశం[i0] = uu____0;
  }
  తిరిగి re;
}

/**
 Call [`deserialize_to_uncompressed_ring_element`] for each ring element.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.deserialize_vector
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cpa_deserialize_సదిశ_68(
  Eurydice_borrow_ముక్క_u8 secret_కీలకం,
  Eurydice_arr_bb0 *secret_as_ntt
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_serialize_deserialize_గమ్యం_uncompressed_ring_element_ea(Eurydice_ముక్క_subslice_shared_c8(secret_కీలకం,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ప్రారంభం = i0 * LIBCRUX_ML_KEM_CONSTANTS_బైట్లు_చొప్పున_RING_ELEMENT,
              .చివర = (i0 + (కొలత_t)1U) * LIBCRUX_ML_KEM_CONSTANTS_బైట్లు_చొప్పున_RING_ELEMENT
            }
          )));
    secret_as_ntt->దత్తాంశం[i0] = uu____0;
  }
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::ind_cpa::deserialize_then_decompress_u::closure<Vector, K, CIPHERTEXT_SIZE, U_COMPRESSION_FACTOR>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.deserialize_then_decompress_u.call_mut_35
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- U_COMPRESSION_FACTOR= 10
*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_30(
  శూన్య **_,
  కొలత_t tupled_వాదనలు
)
{
  తిరిగి libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 10
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_compress_decompress_ciphertext_coefficient_ef(Eurydice_arr_d6 a)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.దత్తాంశం[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_ప్రజా_integers_classify_27_39(LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_MODULUS));
    decompressed = (int32_t)((uint32_t)decompressed << 1U) + (int32_t)((uint32_t)1 << (uint32_t)10);
    decompressed >>= (uint32_t)(10 + 1);
    a.దత్తాంశం[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  తిరిగి a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 10
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_decompress_ciphertext_coefficient_b8_ef(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_compress_decompress_ciphertext_coefficient_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(Eurydice_borrow_ముక్క_u8 serialized)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  కొరకు (కొలత_t i = (కొలత_t)0U; i < serialized.meta / (కొలత_t)20U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)20U,
            .చివర = i0 * (కొలత_t)20U + (కొలత_t)20U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_సదిశ_portable_deserialize_10_b8(బైట్లు);
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_సదిశ_portable_decompress_ciphertext_coefficient_b8_ef(coefficient);
    re.దత్తాంశం[i0] = uu____0;
  }
  తిరిగి re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_f7(
  Eurydice_borrow_ముక్క_u8 serialized
)
{
  తిరిగి libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(serialized);
}

రకనిర్వచనం నిర్మాణం libcrux_ml_kem_సదిశ_portable_సదిశ_type_Portable_సదిశ_x2_s
{
  Eurydice_arr_d6 fst;
  Eurydice_arr_d6 snd;
}
libcrux_ml_kem_సదిశ_portable_సదిశ_type_Portable_సదిశ_x2;

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_layer_int_vec_step
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE libcrux_ml_kem_సదిశ_portable_సదిశ_type_Portable_సదిశ_x2
libcrux_ml_kem_ntt_ntt_layer_int_vec_అడుగు_ea(
  Eurydice_arr_d6 a,
  Eurydice_arr_d6 b,
  int16_t zeta_r
)
{
  Eurydice_arr_d6
  t = libcrux_ml_kem_సదిశ_portable_montgomery_multiply_by_constant_b8(b, zeta_r);
  b = libcrux_ml_kem_సదిశ_portable_sub_b8(a, &t);
  a = libcrux_ml_kem_సదిశ_portable_కూడు_b8(a, &t);
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_kem_సదిశ_portable_సదిశ_type_Portable_సదిశ_x2){
        .fst = a,
        .snd = b
      }
    );
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_4_plus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(
  కొలత_t *zeta_i,
  Eurydice_arr_9e *re,
  కొలత_t layer,
  కొలత_t _initial_coefficient_bound
)
{
  కొలత_t అడుగు = (కొలత_t)1U << (uint32_t)layer;
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < (కొలత_t)128U >> (uint32_t)layer; i0++)
  {
    కొలత_t విడత = i0;
    zeta_i[0U]++;
    కొలత_t స్థానభ్రంశం = విడత * అడుగు * (కొలత_t)2U;
    కొలత_t స్థానభ్రంశం_vec = స్థానభ్రంశం / (కొలత_t)16U;
    కొలత_t అడుగు_vec = అడుగు / (కొలత_t)16U;
    కొరకు (కొలత_t i = స్థానభ్రంశం_vec; i < స్థానభ్రంశం_vec + అడుగు_vec; i++)
    {
      కొలత_t j = i;
      libcrux_ml_kem_సదిశ_portable_సదిశ_type_Portable_సదిశ_x2
      uu____0 =
        libcrux_ml_kem_ntt_ntt_layer_int_vec_అడుగు_ea(re->దత్తాంశం[j],
          re->దత్తాంశం[j + అడుగు_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_d6 x = uu____0.fst;
      Eurydice_arr_d6 y = uu____0.snd;
      re->దత్తాంశం[j] = x;
      re->దత్తాంశం[j + అడుగు_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ntt_ntt_at_layer_3_ea(
  కొలత_t *zeta_i,
  Eurydice_arr_9e *re,
  కొలత_t _initial_coefficient_bound
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    కొలత_t విడత = i;
    zeta_i[0U]++;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_సదిశ_portable_ntt_layer_3_అడుగు_b8(re->దత్తాంశం[విడత],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->దత్తాంశం[విడత] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ntt_ntt_at_layer_2_ea(
  కొలత_t *zeta_i,
  Eurydice_arr_9e *re,
  కొలత_t _initial_coefficient_bound
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    కొలత_t విడత = i;
    zeta_i[0U]++;
    re->దత్తాంశం[విడత] =
      libcrux_ml_kem_సదిశ_portable_ntt_layer_2_అడుగు_b8(re->దత్తాంశం[విడత],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (కొలత_t)1U));
    zeta_i[0U]++;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ntt_ntt_at_layer_1_ea(
  కొలత_t *zeta_i,
  Eurydice_arr_9e *re,
  కొలత_t _initial_coefficient_bound
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    కొలత_t విడత = i;
    zeta_i[0U]++;
    re->దత్తాంశం[విడత] =
      libcrux_ml_kem_సదిశ_portable_ntt_layer_1_అడుగు_b8(re->దత్తాంశం[విడత],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (కొలత_t)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (కొలత_t)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (కొలత_t)3U));
    zeta_i[0U] += (కొలత_t)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.poly_barrett_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_polynomial_poly_barrett_reduce_ea(Eurydice_arr_9e *myself)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_సదిశ_portable_barrett_reduce_b8(myself->దత్తాంశం[i0]);
    myself->దత్తాంశం[i0] = uu____0;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.poly_barrett_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(Eurydice_arr_9e *self)
{
  libcrux_ml_kem_polynomial_poly_barrett_reduce_ea(self);
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_vector_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- VECTOR_U_COMPRESSION_FACTOR= 10
*/
స్థిర KRML_MUSTINLINE శూన్య libcrux_ml_kem_ntt_ntt_సదిశ_u_f7(Eurydice_arr_9e *re)
{
  కొలత_t zeta_i = (కొలత_t)0U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (కొలత_t)7U, (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (కొలత_t)6U, (కొలత_t)2U * (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (కొలత_t)5U, (కొలత_t)3U * (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (కొలత_t)4U, (కొలత_t)4U * (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (కొలత_t)5U * (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (కొలత_t)6U * (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (కొలత_t)7U * (కొలత_t)3328U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
 Call [`deserialize_then_decompress_ring_element_u`] on each ring element
 in the `ciphertext`.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.deserialize_then_decompress_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- U_COMPRESSION_FACTOR= 10
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_30(స్థిరరాశి Eurydice_arr_2b *ciphertext)
{
  Eurydice_arr_bb0 arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_struct.దత్తాంశం[i] =
      libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_30(&lvalue,
        i);
  }
  Eurydice_arr_bb0 u_as_ntt = arr_struct;
  కొరకు
  (కొలత_t
    i = (కొలత_t)0U;
    i <
      (కొలత_t)1088U /
        (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * (కొలత_t)10U / (కొలత_t)8U);
    i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    u_బైట్లు =
      Eurydice_array_గమ్యం_subslice_shared_d44(ciphertext,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 *
              (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * (కొలత_t)10U / (కొలత_t)8U),
            .చివర = i0 *
              (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * (కొలత_t)10U / (కొలత_t)8U)
            + LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT * (కొలత_t)10U / (కొలత_t)8U
          }
        ));
    u_as_ntt.దత్తాంశం[i0] =
      libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_f7(u_బైట్లు);
    libcrux_ml_kem_ntt_ntt_సదిశ_u_f7(&u_as_ntt.దత్తాంశం[i0]);
  }
  తిరిగి u_as_ntt;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 4
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_compress_decompress_ciphertext_coefficient_d1(Eurydice_arr_d6 a)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.దత్తాంశం[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_ప్రజా_integers_classify_27_39(LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_MODULUS));
    decompressed = (int32_t)((uint32_t)decompressed << 1U) + (int32_t)((uint32_t)1 << (uint32_t)4);
    decompressed >>= (uint32_t)(4 + 1);
    a.దత్తాంశం[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  తిరిగి a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 4
*/
స్థిర అంతఃవరుస Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_decompress_ciphertext_coefficient_b8_d1(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_compress_decompress_ciphertext_coefficient_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(Eurydice_borrow_ముక్క_u8 serialized)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  కొరకు (కొలత_t i = (కొలత_t)0U; i < serialized.meta / (కొలత_t)8U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)8U,
            .చివర = i0 * (కొలత_t)8U + (కొలత_t)8U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_సదిశ_portable_deserialize_4_b8(బైట్లు);
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_సదిశ_portable_decompress_ciphertext_coefficient_b8_d1(coefficient);
    re.దత్తాంశం[i0] = uu____0;
  }
  తిరిగి re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- COMPRESSION_FACTOR= 4
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_b6(
  Eurydice_borrow_ముక్క_u8 serialized
)
{
  తిరిగి libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(serialized);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర అంతఃవరుస Eurydice_arr_9e libcrux_ml_kem_polynomial_ZERO_ea(శూన్య)
{
  Eurydice_arr_9e lit;
  Eurydice_arr_d6 repeat_వ్యక్తీకరణ[16U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_ml_kem_సదిశ_portable_ZERO_b8();
  }
  జ్ఞాపకం_నకలు(lit.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)16U * పరిమాణం (Eurydice_arr_d6));
  తిరిగి lit;
}

/**
 Given two `KyberPolynomialRingElement`s in their NTT representations,
 compute their product. Given two polynomials in the NTT domain `f^` and `ĵ`,
 the `iᵗʰ` coefficient of the product `k̂` is determined by the calculation:

 ```plaintext
 ĥ[2·i] + ĥ[2·i + 1]X = (f^[2·i] + f^[2·i + 1]X)·(ĝ[2·i] + ĝ[2·i + 1]X) mod (X² - ζ^(2·BitRev₇(i) + 1))
 ```

 This function almost implements <strong>Algorithm 10</strong> of the
 NIST FIPS 203 standard, which is reproduced below:

 ```plaintext
 Input: Two arrays fˆ ∈ ℤ₂₅₆ and ĝ ∈ ℤ₂₅₆.
 Output: An array ĥ ∈ ℤq.

 for(i ← 0; i < 128; i++)
     (ĥ[2i], ĥ[2i+1]) ← BaseCaseMultiply(fˆ[2i], fˆ[2i+1], ĝ[2i], ĝ[2i+1], ζ^(2·BitRev₇(i) + 1))
 end for
 return ĥ
 ```
 We say "almost" because the coefficients of the ring element output by
 this function are in the Montgomery domain.

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ntt_multiply
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ntt_multiply_ea(
  స్థిరరాశి Eurydice_arr_9e *myself,
  స్థిరరాశి Eurydice_arr_9e *rhs
)
{
  Eurydice_arr_9e బహిర్గతం = libcrux_ml_kem_polynomial_ZERO_ea();
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_సదిశ_portable_ntt_multiply_b8(&myself->దత్తాంశం[i0],
        &rhs->దత్తాంశం[i0],
        libcrux_ml_kem_polynomial_zeta((కొలత_t)64U + (కొలత_t)4U * i0),
        libcrux_ml_kem_polynomial_zeta((కొలత_t)64U + (కొలత_t)4U * i0 + (కొలత_t)1U),
        libcrux_ml_kem_polynomial_zeta((కొలత_t)64U + (కొలత_t)4U * i0 + (కొలత_t)2U),
        libcrux_ml_kem_polynomial_zeta((కొలత_t)64U + (కొలత_t)4U * i0 + (కొలత_t)3U));
    బహిర్గతం.దత్తాంశం[i0] = uu____0;
  }
  తిరిగి బహిర్గతం;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ntt_multiply_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(
  స్థిరరాశి Eurydice_arr_9e *self,
  స్థిరరాశి Eurydice_arr_9e *rhs
)
{
  తిరిగి libcrux_ml_kem_polynomial_ntt_multiply_ea(self, rhs);
}

/**
 Given two polynomial ring elements `lhs` and `rhs`, compute the pointwise
 sum of their constituent coefficients.
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_to_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_polynomial_కూడు_గమ్యం_ring_element_68(
  Eurydice_arr_9e *myself,
  స్థిరరాశి Eurydice_arr_9e *rhs
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_సదిశ_portable_కూడు_b8(myself->దత్తాంశం[i0], &rhs->దత్తాంశం[i0]);
    myself->దత్తాంశం[i0] = uu____0;
  }
}

/**
 Given two polynomial ring elements `lhs` and `rhs`, compute the pointwise
 sum of their constituent coefficients.
*/
/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_to_ring_element_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_polynomial_కూడు_గమ్యం_ring_element_d6_68(
  Eurydice_arr_9e *self,
  స్థిరరాశి Eurydice_arr_9e *rhs
)
{
  libcrux_ml_kem_polynomial_కూడు_గమ్యం_ring_element_68(self, rhs);
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(కొలత_t *zeta_i, Eurydice_arr_9e *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    కొలత_t విడత = i;
    zeta_i[0U]--;
    re->దత్తాంశం[విడత] =
      libcrux_ml_kem_సదిశ_portable_inv_ntt_layer_1_అడుగు_b8(re->దత్తాంశం[విడత],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (కొలత_t)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (కొలత_t)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (కొలత_t)3U));
    zeta_i[0U] -= (కొలత_t)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(కొలత_t *zeta_i, Eurydice_arr_9e *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    కొలత_t విడత = i;
    zeta_i[0U]--;
    re->దత్తాంశం[విడత] =
      libcrux_ml_kem_సదిశ_portable_inv_ntt_layer_2_అడుగు_b8(re->దత్తాంశం[విడత],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (కొలత_t)1U));
    zeta_i[0U]--;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(కొలత_t *zeta_i, Eurydice_arr_9e *re)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    కొలత_t విడత = i;
    zeta_i[0U]--;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_సదిశ_portable_inv_ntt_layer_3_అడుగు_b8(re->దత్తాంశం[విడత],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->దత్తాంశం[విడత] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.inv_ntt_layer_int_vec_step_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE libcrux_ml_kem_సదిశ_portable_సదిశ_type_Portable_సదిశ_x2
libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_అడుగు_reduce_ea(
  Eurydice_arr_d6 a,
  Eurydice_arr_d6 b,
  int16_t zeta_r
)
{
  Eurydice_arr_d6 a_minus_b = libcrux_ml_kem_సదిశ_portable_sub_b8(b, &a);
  a =
    libcrux_ml_kem_సదిశ_portable_barrett_reduce_b8(libcrux_ml_kem_సదిశ_portable_కూడు_b8(a, &b));
  b = libcrux_ml_kem_సదిశ_portable_montgomery_multiply_by_constant_b8(a_minus_b, zeta_r);
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_kem_సదిశ_portable_సదిశ_type_Portable_సదిశ_x2){
        .fst = a,
        .snd = b
      }
    );
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_4_plus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(
  కొలత_t *zeta_i,
  Eurydice_arr_9e *re,
  కొలత_t layer
)
{
  కొలత_t అడుగు = (కొలత_t)1U << (uint32_t)layer;
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < (కొలత_t)128U >> (uint32_t)layer; i0++)
  {
    కొలత_t విడత = i0;
    zeta_i[0U]--;
    కొలత_t స్థానభ్రంశం = విడత * అడుగు * (కొలత_t)2U;
    కొలత_t స్థానభ్రంశం_vec = స్థానభ్రంశం / LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ;
    కొలత_t అడుగు_vec = అడుగు / LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ;
    కొరకు (కొలత_t i = స్థానభ్రంశం_vec; i < స్థానభ్రంశం_vec + అడుగు_vec; i++)
    {
      కొలత_t j = i;
      libcrux_ml_kem_సదిశ_portable_సదిశ_type_Portable_సదిశ_x2
      uu____0 =
        libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_అడుగు_reduce_ea(re->దత్తాంశం[j],
          re->దత్తాంశం[j + అడుగు_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_d6 x = uu____0.fst;
      Eurydice_arr_d6 y = uu____0.snd;
      re->దత్తాంశం[j] = x;
      re->దత్తాంశం[j + అడుగు_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_montgomery
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(Eurydice_arr_9e *re)
{
  కొలత_t zeta_i = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT / (కొలత_t)2U;
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (కొలత_t)4U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (కొలత_t)5U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (కొలత_t)6U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (కొలత_t)7U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_వ్యవకలనం_reduce_ea(స్థిరరాశి Eurydice_arr_9e *myself, Eurydice_arr_9e b)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    coefficient_సాధారణ_form =
      libcrux_ml_kem_సదిశ_portable_montgomery_multiply_by_constant_b8(b.దత్తాంశం[i0],
        1441);
    Eurydice_arr_d6
    diff = libcrux_ml_kem_సదిశ_portable_sub_b8(myself->దత్తాంశం[i0], &coefficient_సాధారణ_form);
    Eurydice_arr_d6 red = libcrux_ml_kem_సదిశ_portable_barrett_reduce_b8(diff);
    b.దత్తాంశం[i0] = red;
  }
  తిరిగి b;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_వ్యవకలనం_reduce_d6_ea(స్థిరరాశి Eurydice_arr_9e *self, Eurydice_arr_9e b)
{
  తిరిగి libcrux_ml_kem_polynomial_వ్యవకలనం_reduce_ea(self, b);
}

/**
 The following functions compute various expressions involving
 vectors and matrices. The computation of these expressions has been
 abstracted away into these functions in order to save on loop iterations.
 Compute v − InverseNTT(sᵀ ◦ NTT(u))
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_మాతృక_compute_సందేశం_68(
  స్థిరరాశి Eurydice_arr_9e *v,
  స్థిరరాశి Eurydice_arr_bb0 *secret_as_ntt,
  స్థిరరాశి Eurydice_arr_bb0 *u_as_ntt
)
{
  Eurydice_arr_9e ఫలితం = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_9e
    లబ్ధం =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&secret_as_ntt->దత్తాంశం[i0],
        &u_as_ntt->దత్తాంశం[i0]);
    libcrux_ml_kem_polynomial_కూడు_గమ్యం_ring_element_d6_68(&ఫలితం, &లబ్ధం);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&ఫలితం);
  తిరిగి libcrux_ml_kem_polynomial_వ్యవకలనం_reduce_d6_ea(v, ఫలితం);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.to_unsigned_field_modulus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_serialize_గమ్యం_unsigned_క్షేత్రం_modulus_ea(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_గమ్యం_unsigned_representative_b8(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_serialize_compress_then_serialize_సందేశం_ea(Eurydice_arr_9e re)
{
  Eurydice_arr_ec serialized = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    coefficient = libcrux_ml_kem_serialize_గమ్యం_unsigned_క్షేత్రం_modulus_ea(re.దత్తాంశం[i0]);
    Eurydice_arr_d6
    coefficient_compressed = libcrux_ml_kem_సదిశ_portable_compress_1_b8(coefficient);
    Eurydice_array_u8x2
    బైట్లు = libcrux_ml_kem_సదిశ_portable_serialize_1_b8(coefficient_compressed);
    Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d46(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = (కొలత_t)2U * i0,
            .చివర = (కొలత_t)2U * i0 + (కొలత_t)2U
          }
        )),
      Eurydice_array_గమ్యం_ముక్క_shared_82(&బైట్లు),
      uint8_t);
  }
  తిరిగి serialized;
}

/**
 This function implements <strong>Algorithm 14</strong> of the
 NIST FIPS 203 specification; this is the Kyber CPA-PKE decryption algorithm.

 Algorithm 14 is reproduced below:

 ```plaintext
 Input: decryption key dkₚₖₑ ∈ 𝔹^{384k}.
 Input: ciphertext c ∈ 𝔹^{32(dᵤk + dᵥ)}.
 Output: message m ∈ 𝔹^{32}.

 c₁ ← c[0 : 32dᵤk]
 c₂ ← c[32dᵤk : 32(dᵤk + dᵥ)]
 u ← Decompress_{dᵤ}(ByteDecode_{dᵤ}(c₁))
 v ← Decompress_{dᵥ}(ByteDecode_{dᵥ}(c₂))
 ŝ ← ByteDecode₁₂(dkₚₖₑ)
 w ← v - NTT-¹(ŝᵀ ◦ NTT(u))
 m ← ByteEncode₁(Compress₁(w))
 return m
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.decrypt_unpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- VECTOR_U_ENCODED_SIZE= 960
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(
  స్థిరరాశి Eurydice_arr_bb0 *secret_కీలకం,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_bb0
  u_as_ntt = libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_30(ciphertext);
  Eurydice_arr_9e
  v =
    libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_b6(Eurydice_array_గమ్యం_subslice_from_shared_5f0(ciphertext,
        (కొలత_t)960U));
  Eurydice_arr_9e సందేశం_2 = libcrux_ml_kem_మాతృక_compute_సందేశం_68(&v, secret_కీలకం, &u_as_ntt);
  తిరిగి libcrux_ml_kem_serialize_compress_then_serialize_సందేశం_ea(సందేశం_2);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.decrypt
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- VECTOR_U_ENCODED_SIZE= 960
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cpa_decrypt_01(
  Eurydice_borrow_ముక్క_u8 secret_కీలకం,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_bb0 arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_struct.దత్తాంశం[i] = libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_01(&lvalue, i);
  }
  Eurydice_arr_bb0 secret_కీలకం_unpacked = arr_struct;
  libcrux_ml_kem_ind_cpa_deserialize_సదిశ_68(secret_కీలకం, &secret_కీలకం_unpacked);
  తిరిగి libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(&secret_కీలకం_unpacked, ciphertext);
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.G_4a
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_c7
libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_borrow_ముక్క_u8 ఆదానం)
{
  తిరిగి libcrux_ml_kem_hash_functions_portable_G(ఆదానం);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 32
*/
స్థిర అంతఃవరుస Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_PRF_ce(Eurydice_borrow_ముక్క_u8 ఆదానం)
{
  Eurydice_arr_ec digest = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_గమ్యం_ముక్క_mut_01(&digest), ఆదానం);
  తిరిగి digest;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF_4a
with const generics
- K= 3
- LEN= 32
*/
స్థిర అంతఃవరుస Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_borrow_ముక్క_u8 ఆదానం)
{
  తిరిగి libcrux_ml_kem_hash_functions_portable_PRF_ce(ఆదానం);
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_bb0
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం Eurydice_arr_c10_s { Eurydice_arr_bb0 దత్తాంశం[3U]; } Eurydice_arr_c10;

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.IndCpaPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51_s
{
  Eurydice_arr_bb0 t_as_ntt;
  Eurydice_arr_ec విత్తనం_for_A;
  Eurydice_arr_c10 A;
}
libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51;

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.default_8b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర అంతఃవరుస libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51
libcrux_ml_kem_ind_cpa_unpacked_default_8b_68(శూన్య)
{
  Eurydice_arr_bb0 uu____0;
  Eurydice_arr_9e repeat_expression0[3U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    repeat_expression0[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  జ్ఞాపకం_నకలు(uu____0.దత్తాంశం, repeat_expression0, (కొలత_t)3U * పరిమాణం (Eurydice_arr_9e));
  Eurydice_arr_ec uu____1 = { .దత్తాంశం = { 0U } };
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51 lit0;
  lit0.t_as_ntt = uu____0;
  lit0.విత్తనం_for_A = uu____1;
  Eurydice_arr_bb0 repeat_expression1[3U];
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < (కొలత_t)3U; i0++)
  {
    Eurydice_arr_bb0 lit;
    Eurydice_arr_9e repeat_వ్యక్తీకరణ[3U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
    {
      repeat_వ్యక్తీకరణ[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    }
    జ్ఞాపకం_నకలు(lit.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)3U * పరిమాణం (Eurydice_arr_9e));
    repeat_expression1[i0] = lit;
  }
  జ్ఞాపకం_నకలు(lit0.A.దత్తాంశం, repeat_expression1, (కొలత_t)3U * పరిమాణం (Eurydice_arr_bb0));
  తిరిగి lit0;
}

/**
 Only use with public values.

 This MUST NOT be used with secret inputs, like its caller `deserialize_ring_elements_reduced`.
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_to_reduced_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_గమ్యం_reduced_ring_element_ea(
  Eurydice_borrow_ముక్క_u8 serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  కొరకు (కొలత_t i = (కొలత_t)0U; i < serialized.meta / (కొలత_t)24U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    బైట్లు =
      Eurydice_ముక్క_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * (కొలత_t)24U,
            .చివర = i0 * (కొలత_t)24U + (కొలత_t)24U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_సదిశ_portable_deserialize_12_b8(బైట్లు);
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_సదిశ_portable_cond_వ్యవకలనం_3329_b8(coefficient);
    re.దత్తాంశం[i0] = uu____0;
  }
  తిరిగి re;
}

/**
 See [deserialize_ring_elements_reduced_out].
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_ring_elements_reduced
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(
  Eurydice_borrow_ముక్క_u8 ప్రజా_కీలకం,
  Eurydice_arr_bb0 *deserialized_pk
)
{
  కొరకు
  (కొలత_t
    i = (కొలత_t)0U;
    i < ప్రజా_కీలకం.meta / LIBCRUX_ML_KEM_CONSTANTS_బైట్లు_చొప్పున_RING_ELEMENT;
    i++)
  {
    కొలత_t i0 = i;
    Eurydice_borrow_ముక్క_u8
    ring_element =
      Eurydice_ముక్క_subslice_shared_c8(ప్రజా_కీలకం,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_KEM_CONSTANTS_బైట్లు_చొప్పున_RING_ELEMENT,
            .చివర = i0 * LIBCRUX_ML_KEM_CONSTANTS_బైట్లు_చొప్పున_RING_ELEMENT +
              LIBCRUX_ML_KEM_CONSTANTS_బైట్లు_చొప్పున_RING_ELEMENT
          }
        ));
    Eurydice_arr_9e
    uu____0 = libcrux_ml_kem_serialize_deserialize_గమ్యం_reduced_ring_element_ea(ring_element);
    deserialized_pk->దత్తాంశం[i0] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_1b0
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_78(
  స్థిరరాశి Eurydice_arr_810 *ఆదానం
)
{
  Eurydice_arr_1b0 shake128_state;
  Eurydice_arr_7c repeat_వ్యక్తీకరణ[3U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_sha3_portable_incremental_shake128_init();
  }
  జ్ఞాపకం_నకలు(shake128_state.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)3U * పరిమాణం (Eurydice_arr_7c));
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_absorb_final(&shake128_state.దత్తాంశం[i0],
      Eurydice_array_గమ్యం_ముక్క_shared_e9(&ఆదానం->దత్తాంశం[i0]));
  }
  తిరిగి shake128_state;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final_4a
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_1b0
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_78(
  స్థిరరాశి Eurydice_arr_810 *ఆదానం
)
{
  తిరిగి libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_78(ఆదానం);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_మొదటి_three_ఖండాలు_78(
  Eurydice_arr_1b0 *st
)
{
  Eurydice_arr_7e
  బహిర్గతం = { .దత్తాంశం = { { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } } } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_మొదటి_three_ఖండాలు(&st->దత్తాంశం[i0],
      Eurydice_array_గమ్యం_ముక్క_mut_48(&బహిర్గతం.దత్తాంశం[i0]));
  }
  తిరిగి బహిర్గతం;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks_4a
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_మొదటి_three_ఖండాలు_4a_78(
  Eurydice_arr_1b0 *self
)
{
  తిరిగి libcrux_ml_kem_hash_functions_portable_shake128_squeeze_మొదటి_three_ఖండాలు_78(self);
}

/**
 If `bytes` contains a set of uniformly random bytes, this function
 uniformly samples a ring element `â` that is treated as being the NTT representation
 of the corresponding polynomial `a`.

 Since rejection sampling is used, it is possible the supplied bytes are
 not enough to sample the element, in which case an `Err` is returned and the
 caller must try again with a fresh set of bytes.

 This function <strong>partially</strong> implements <strong>Algorithm 6</strong> of the NIST FIPS 203 standard,
 We say "partially" because this implementation only accepts a finite set of
 bytes as input and returns an error if the set is not enough; Algorithm 6 of
 the FIPS 203 standard on the other hand samples from an infinite stream of bytes
 until the ring element is filled. Algorithm 6 is reproduced below:

 ```plaintext
 Input: byte stream B ∈ 𝔹*.
 Output: array â ∈ ℤ₂₅₆.

 i ← 0
 j ← 0
 while j < 256 do
     d₁ ← B[i] + 256·(B[i+1] mod 16)
     d₂ ← ⌊B[i+1]/16⌋ + 16·B[i+2]
     if d₁ < q then
         â[j] ← d₁
         j ← j + 1
     end if
     if d₂ < q and j < 256 then
         â[j] ← d₂
         j ← j + 1
     end if
     i ← i + 3
 end while
 return â
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_uniform_distribution_next
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- N= 504
*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_ఏకరీతి_distribution_తదుపరి_b6(
  స్థిరరాశి Eurydice_arr_7e *randomness,
  Eurydice_arr_eb *sampled_coefficients,
  Eurydice_arr_b1 *బహిర్గతం
)
{
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < (కొలత_t)3U; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)504U / (కొలత_t)24U; i++)
    {
      కొలత_t r = i;
      ఒకవేళ (sampled_coefficients->దత్తాంశం[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT)
      {
        కొలత_t
        sampled =
          libcrux_ml_kem_సదిశ_portable_rej_sample_b8(Eurydice_array_గమ్యం_subslice_shared_d45(&randomness->దత్తాంశం[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .ప్రారంభం = r * (కొలత_t)24U,
                  .చివర = r * (కొలత_t)24U + (కొలత_t)24U
                }
              )),
            Eurydice_array_గమ్యం_subslice_mut_e7(&బహిర్గతం->దత్తాంశం[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .ప్రారంభం = sampled_coefficients->దత్తాంశం[i1],
                  .చివర = sampled_coefficients->దత్తాంశం[i1] + (కొలత_t)16U
                }
              )));
        కొలత_t uu____0 = i1;
        sampled_coefficients->దత్తాంశం[uu____0] += sampled;
      }
    }
  }
  bool పూర్తి = true;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    ఒకవేళ (sampled_coefficients->దత్తాంశం[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT)
    {
      sampled_coefficients->దత్తాంశం[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT;
    }
    లేకపోతే
    {
      పూర్తి = false;
    }
  }
  తిరిగి పూర్తి;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_2c
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_తదుపరి_ఖండం_78(Eurydice_arr_1b0 *st)
{
  Eurydice_arr_2c
  బహిర్గతం = { .దత్తాంశం = { { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } } } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_తదుపరి_ఖండం(&st->దత్తాంశం[i0],
      Eurydice_array_గమ్యం_ముక్క_mut_2c(&బహిర్గతం.దత్తాంశం[i0]));
  }
  తిరిగి బహిర్గతం;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block_4a
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_2c
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_తదుపరి_ఖండం_4a_78(
  Eurydice_arr_1b0 *self
)
{
  తిరిగి libcrux_ml_kem_hash_functions_portable_shake128_squeeze_తదుపరి_ఖండం_78(self);
}

/**
 If `bytes` contains a set of uniformly random bytes, this function
 uniformly samples a ring element `â` that is treated as being the NTT representation
 of the corresponding polynomial `a`.

 Since rejection sampling is used, it is possible the supplied bytes are
 not enough to sample the element, in which case an `Err` is returned and the
 caller must try again with a fresh set of bytes.

 This function <strong>partially</strong> implements <strong>Algorithm 6</strong> of the NIST FIPS 203 standard,
 We say "partially" because this implementation only accepts a finite set of
 bytes as input and returns an error if the set is not enough; Algorithm 6 of
 the FIPS 203 standard on the other hand samples from an infinite stream of bytes
 until the ring element is filled. Algorithm 6 is reproduced below:

 ```plaintext
 Input: byte stream B ∈ 𝔹*.
 Output: array â ∈ ℤ₂₅₆.

 i ← 0
 j ← 0
 while j < 256 do
     d₁ ← B[i] + 256·(B[i+1] mod 16)
     d₂ ← ⌊B[i+1]/16⌋ + 16·B[i+2]
     if d₁ < q then
         â[j] ← d₁
         j ← j + 1
     end if
     if d₂ < q and j < 256 then
         â[j] ← d₂
         j ← j + 1
     end if
     i ← i + 3
 end while
 return â
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_uniform_distribution_next
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- N= 168
*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_ఏకరీతి_distribution_తదుపరి_b60(
  స్థిరరాశి Eurydice_arr_2c *randomness,
  Eurydice_arr_eb *sampled_coefficients,
  Eurydice_arr_b1 *బహిర్గతం
)
{
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < (కొలత_t)3U; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)168U / (కొలత_t)24U; i++)
    {
      కొలత_t r = i;
      ఒకవేళ (sampled_coefficients->దత్తాంశం[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT)
      {
        కొలత_t
        sampled =
          libcrux_ml_kem_సదిశ_portable_rej_sample_b8(Eurydice_array_గమ్యం_subslice_shared_d46(&randomness->దత్తాంశం[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .ప్రారంభం = r * (కొలత_t)24U,
                  .చివర = r * (కొలత_t)24U + (కొలత_t)24U
                }
              )),
            Eurydice_array_గమ్యం_subslice_mut_e7(&బహిర్గతం->దత్తాంశం[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .ప్రారంభం = sampled_coefficients->దత్తాంశం[i1],
                  .చివర = sampled_coefficients->దత్తాంశం[i1] + (కొలత_t)16U
                }
              )));
        కొలత_t uu____0 = i1;
        sampled_coefficients->దత్తాంశం[uu____0] += sampled;
      }
    }
  }
  bool పూర్తి = true;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    ఒకవేళ (sampled_coefficients->దత్తాంశం[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT)
    {
      sampled_coefficients->దత్తాంశం[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_లోపల_RING_ELEMENT;
    }
    లేకపోతే
    {
      పూర్తి = false;
    }
  }
  తిరిగి పూర్తి;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_from_i16_array_ea(Eurydice_borrow_ముక్క_i16 a)
{
  Eurydice_arr_9e ఫలితం = libcrux_ml_kem_polynomial_ZERO_ea();
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_సదిశ_portable_from_i16_array_b8(Eurydice_ముక్క_subslice_shared_a6(a,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ప్రారంభం = i0 * (కొలత_t)16U,
              .చివర = (i0 + (కొలత_t)1U) * (కొలత_t)16U
            }
          )));
    ఫలితం.దత్తాంశం[i0] = uu____0;
  }
  తిరిగి ఫలితం;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_borrow_ముక్క_i16 a)
{
  తిరిగి libcrux_ml_kem_polynomial_from_i16_array_ea(a);
}

/**
This function found in impl {core::ops::function::FnMut<([i16; 272usize]), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]> for libcrux_ml_kem::sampling::sample_from_xof::closure<Vector, Hasher, K>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3]}
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_xof.call_mut_0a
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_xof_call_mut_0a_91(శూన్య **_, Eurydice_arr_5b tupled_వాదనలు)
{
  Eurydice_arr_5b s = tupled_వాదనలు;
  తిరిగి
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_గమ్యం_subslice_shared_e70(&s,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)256U })));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_xof
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_sampling_sample_from_xof_91(స్థిరరాశి Eurydice_arr_810 *seeds)
{
  Eurydice_arr_eb sampled_coefficients = { .దత్తాంశం = { 0U } };
  Eurydice_arr_b1
  బహిర్గతం = { .దత్తాంశం = { { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } } } };
  Eurydice_arr_1b0
  xof_state = libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_78(seeds);
  Eurydice_arr_7e
  randomness0 =
    libcrux_ml_kem_hash_functions_portable_shake128_squeeze_మొదటి_three_ఖండాలు_4a_78(&xof_state);
  bool
  పూర్తి =
    libcrux_ml_kem_sampling_sample_from_ఏకరీతి_distribution_తదుపరి_b6(&randomness0,
      &sampled_coefficients,
      &బహిర్గతం);
  అయితే (true)
  {
    ఒకవేళ (పూర్తి)
    {
      ఆపు;
    }
    లేకపోతే
    {
      Eurydice_arr_2c
      randomness =
        libcrux_ml_kem_hash_functions_portable_shake128_squeeze_తదుపరి_ఖండం_4a_78(&xof_state);
      పూర్తి =
        libcrux_ml_kem_sampling_sample_from_ఏకరీతి_distribution_తదుపరి_b60(&randomness,
          &sampled_coefficients,
          &బహిర్గతం);
    }
  }
  Eurydice_arr_bb0 arr_mapped_str;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_mapped_str.దత్తాంశం[i] =
      libcrux_ml_kem_sampling_sample_from_xof_call_mut_0a_91(&lvalue,
        బహిర్గతం.దత్తాంశం[i]);
  }
  తిరిగి arr_mapped_str;
}

/**
A monomorphic instance of libcrux_ml_kem.matrix.sample_matrix_A
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_మాతృక_sample_మాతృక_A_91(
  Eurydice_arr_c10 *A_transpose,
  స్థిరరాశి Eurydice_arr_31 *విత్తనం,
  bool transpose
)
{
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < (కొలత_t)3U; i0++)
  {
    కొలత_t i1 = i0;
    Eurydice_arr_810 seeds;
    Eurydice_arr_31 repeat_వ్యక్తీకరణ[3U];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
    {
      repeat_వ్యక్తీకరణ[i] =
        core_array__core__clone__Clone_for__T__N___clone((కొలత_t)34U,
          విత్తనం,
          uint8_t,
          Eurydice_arr_31);
    }
    జ్ఞాపకం_నకలు(seeds.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)3U * పరిమాణం (Eurydice_arr_31));
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
    {
      కొలత_t j = i;
      seeds.దత్తాంశం[j].దత్తాంశం[32U] = (uint8_t)i1;
      seeds.దత్తాంశం[j].దత్తాంశం[33U] = (uint8_t)j;
    }
    Eurydice_arr_bb0 sampled = libcrux_ml_kem_sampling_sample_from_xof_91(&seeds);
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
    {
      కొలత_t j = i;
      Eurydice_arr_9e sample = sampled.దత్తాంశం[j];
      ఒకవేళ (transpose)
      {
        A_transpose->దత్తాంశం[j].దత్తాంశం[i1] = sample;
      }
      లేకపోతే
      {
        A_transpose->దత్తాంశం[i1].దత్తాంశం[j] = sample;
      }
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.build_unpacked_public_key_mut
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cpa_build_unpacked_ప్రజా_కీలకం_mut_05(
  Eurydice_borrow_ముక్క_u8 ప్రజా_కీలకం,
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51 *unpacked_ప్రజా_కీలకం
)
{
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(Eurydice_ముక్క_subslice_గమ్యం_shared_72(ప్రజా_కీలకం,
      (కొలత_t)1152U),
    &unpacked_ప్రజా_కీలకం->t_as_ntt);
  Eurydice_borrow_ముక్క_u8
  విత్తనం = Eurydice_ముక్క_subslice_from_shared_6d(ప్రజా_కీలకం, (కొలత_t)1152U);
  Eurydice_arr_c10 *uu____0 = &unpacked_ప్రజా_కీలకం->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31 lvalue = libcrux_ml_kem_utils_into_padded_array_de(విత్తనం);
  libcrux_ml_kem_మాతృక_sample_మాతృక_A_91(uu____0, &lvalue, false);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.build_unpacked_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
*/
స్థిర KRML_MUSTINLINE libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51
libcrux_ml_kem_ind_cpa_build_unpacked_ప్రజా_కీలకం_05(Eurydice_borrow_ముక్క_u8 ప్రజా_కీలకం)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51
  unpacked_ప్రజా_కీలకం = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68();
  libcrux_ml_kem_ind_cpa_build_unpacked_ప్రజా_కీలకం_mut_05(ప్రజా_కీలకం, &unpacked_ప్రజా_కీలకం);
  తిరిగి unpacked_ప్రజా_కీలకం;
}

/**
A monomorphic instance of n-tuple
with types Eurydice_arr_bb0, libcrux_ml_kem_polynomial_PolynomialRingElement_1d

*/
రకనిర్వచనం నిర్మాణం tuple_c6_s
{
  Eurydice_arr_bb0 fst;
  Eurydice_arr_9e snd;
}
tuple_c6;

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]> for libcrux_ml_kem::ind_cpa::encrypt_c1::closure<Vector, Hasher, K, C1_LEN, U_COMPRESSION_FACTOR, BLOCK_LEN, ETA1, ETA1_RANDOMNESS_SIZE, ETA2, ETA2_RANDOMNESS_SIZE>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c1.call_mut_f1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- C1_LEN= 960
- U_COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_87(శూన్య **_, కొలత_t tupled_వాదనలు)
{
  తిరిగి libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRFxN
with const generics
- K= 3
- LEN= 128
*/
స్థిర అంతఃవరుస Eurydice_arr_58
libcrux_ml_kem_hash_functions_portable_PRFxN_3b(స్థిరరాశి Eurydice_arr_fd *ఆదానం)
{
  Eurydice_arr_58
  బహిర్గతం = { .దత్తాంశం = { { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } }, { .దత్తాంశం = { 0U } } } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    libcrux_sha3_portable_shake256(Eurydice_array_గమ్యం_ముక్క_mut_78(&బహిర్గతం.దత్తాంశం[i0]),
      Eurydice_array_గమ్యం_ముక్క_shared_b5(&ఆదానం->దత్తాంశం[i0]));
  }
  తిరిగి బహిర్గతం;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRFxN_4a
with const generics
- K= 3
- LEN= 128
*/
స్థిర అంతఃవరుస Eurydice_arr_58
libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(స్థిరరాశి Eurydice_arr_fd *ఆదానం)
{
  తిరిగి libcrux_ml_kem_hash_functions_portable_PRFxN_3b(ఆదానం);
}

/**
 Given a series of uniformly random bytes in `randomness`, for some number `eta`,
 the `sample_from_binomial_distribution_{eta}` functions sample
 a ring element from a binomial distribution centered at 0 that uses two sets
 of `eta` coin flips. If, for example,
 `eta = ETA`, each ring coefficient is a value `v` such
 such that `v ∈ {-ETA, -ETA + 1, ..., 0, ..., ETA + 1, ETA}` and:

 ```plaintext
 - If v < 0, Pr[v] = Pr[-v]
 - If v >= 0, Pr[v] = BINOMIAL_COEFFICIENT(2 * ETA; ETA - v) / 2 ^ (2 * ETA)
 ```

 The values `v < 0` are mapped to the appropriate `KyberFieldElement`.

 The expected value is:

 ```plaintext
 E[X] = (-ETA)Pr[-ETA] + (-(ETA - 1))Pr[-(ETA - 1)] + ... + (ETA - 1)Pr[ETA - 1] + (ETA)Pr[ETA]
      = 0 since Pr[-v] = Pr[v] when v < 0.
 ```

 And the variance is:

 ```plaintext
 Var(X) = E[(X - E[X])^2]
        = E[X^2]
        = sum_(v=-ETA to ETA)v^2 * (BINOMIAL_COEFFICIENT(2 * ETA; ETA - v) / 2^(2 * ETA))
        = ETA / 2
 ```

 This function implements <strong>Algorithm 7</strong> of the NIST FIPS 203 standard, which is
 reproduced below:

 ```plaintext
 Input: byte array B ∈ 𝔹^{64η}.
 Output: array f ∈ ℤ₂₅₆.

 b ← BytesToBits(B)
 for (i ← 0; i < 256; i++)
     x ← ∑(j=0 to η - 1) b[2iη + j]
     y ← ∑(j=0 to η - 1) b[2iη + η + j]
     f[i] ← x−y mod q
 end for
 return f
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_binomial_distribution_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_ద్విపద_distribution_2_ea(
  Eurydice_borrow_ముక్క_u8 randomness
)
{
  Eurydice_arr_04 sampled_i16s = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < randomness.meta / (కొలత_t)4U; i0++)
  {
    కొలత_t chunk_సంఖ్య = i0;
    Eurydice_borrow_ముక్క_u8
    byte_chunk =
      Eurydice_ముక్క_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = chunk_సంఖ్య * (కొలత_t)4U,
            .చివర = chunk_సంఖ్య * (కొలత_t)4U + (కొలత_t)4U
          }
        ));
    uint32_t
    random_బిట్లు_as_u32 =
      (((uint32_t)byte_chunk.ptr[0U] | (uint32_t)byte_chunk.ptr[1U] << 8U) |
        (uint32_t)byte_chunk.ptr[2U] << 16U)
      | (uint32_t)byte_chunk.ptr[3U] << 24U;
    uint32_t even_బిట్లు = random_బిట్లు_as_u32 & 1431655765U;
    uint32_t odd_బిట్లు = random_బిట్లు_as_u32 >> 1U & 1431655765U;
    uint32_t coin_toss_outcomes = even_బిట్లు + odd_బిట్లు;
    కొరకు (uint32_t i = 0U; i < 32U / 4U; i++)
    {
      uint32_t outcome_సమితి = i;
      uint32_t outcome_set0 = outcome_సమితి * 4U;
      int16_t outcome_1 = (int16_t)(coin_toss_outcomes >> (uint32_t)outcome_set0 & 3U);
      int16_t outcome_2 = (int16_t)(coin_toss_outcomes >> (uint32_t)(outcome_set0 + 2U) & 3U);
      కొలత_t స్థానభ్రంశం = (కొలత_t)(outcome_set0 >> 2U);
      sampled_i16s.దత్తాంశం[(కొలత_t)8U * chunk_సంఖ్య + స్థానభ్రంశం] = outcome_1 - outcome_2;
    }
  }
  తిరిగి
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_గమ్యం_ముక్క_shared_99(&sampled_i16s));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_binomial_distribution
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- ETA= 2
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_ద్విపద_distribution_66(
  Eurydice_borrow_ముక్క_u8 randomness
)
{
  తిరిగి libcrux_ml_kem_sampling_sample_from_ద్విపద_distribution_2_ea(randomness);
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_7
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య libcrux_ml_kem_ntt_ntt_at_layer_7_ea(Eurydice_arr_9e *re)
{
  కొలత_t అడుగు = LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT / (కొలత_t)2U;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < అడుగు; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_d6
    t = libcrux_ml_kem_సదిశ_portable_multiply_by_constant_b8(re->దత్తాంశం[j + అడుగు], -1600);
    re->దత్తాంశం[j + అడుగు] = libcrux_ml_kem_సదిశ_portable_sub_b8(re->దత్తాంశం[j], &t);
    Eurydice_arr_d6 uu____1 = libcrux_ml_kem_సదిశ_portable_కూడు_b8(re->దత్తాంశం[j], &t);
    re->దత్తాంశం[j] = uu____1;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_binomially_sampled_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(Eurydice_arr_9e *re)
{
  libcrux_ml_kem_ntt_ntt_at_layer_7_ea(re);
  కొలత_t zeta_i = (కొలత_t)1U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (కొలత_t)6U, (కొలత_t)11207U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (కొలత_t)5U,
    (కొలత_t)11207U + (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (కొలత_t)4U,
    (కొలత_t)11207U + (కొలత_t)2U * (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (కొలత_t)11207U + (కొలత_t)3U * (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (కొలత_t)11207U + (కొలత_t)4U * (కొలత_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (కొలత_t)11207U + (కొలత_t)5U * (కొలత_t)3328U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
 Sample a vector of ring elements from a centered binomial distribution and
 convert them into their NTT representations.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.sample_vector_cbd_then_ntt
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- ETA= 2
- ETA_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_సదిశ_cbd_then_ntt_bf(
  Eurydice_arr_bb0 *re_as_ntt,
  స్థిరరాశి Eurydice_arr_fa0 *prf_ఆదానం,
  uint8_t domain_separator
)
{
  Eurydice_arr_fd prf_inputs;
  Eurydice_arr_fa0 repeat_వ్యక్తీకరణ[3U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    repeat_వ్యక్తీకరణ[i] =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)33U,
        prf_ఆదానం,
        uint8_t,
        Eurydice_arr_fa0);
  }
  జ్ఞాపకం_నకలు(prf_inputs.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)3U * పరిమాణం (Eurydice_arr_fa0));
  domain_separator = libcrux_ml_kem_utils_prf_ఆదానం_inc_78(&prf_inputs, domain_separator);
  Eurydice_arr_58 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(&prf_inputs);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_ద్విపద_distribution_66(Eurydice_array_గమ్యం_ముక్క_shared_78(&prf_outputs.దత్తాంశం[i0]));
    re_as_ntt->దత్తాంశం[i0] = uu____0;
    libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(&re_as_ntt->దత్తాంశం[i0]);
  }
  తిరిగి domain_separator;
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]> for libcrux_ml_kem::ind_cpa::encrypt_c1::closure#1<Vector, Hasher, K, C1_LEN, U_COMPRESSION_FACTOR, BLOCK_LEN, ETA1, ETA1_RANDOMNESS_SIZE, ETA2, ETA2_RANDOMNESS_SIZE>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c1.call_mut_dd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- C1_LEN= 960
- U_COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_87(శూన్య **_, కొలత_t tupled_వాదనలు)
{
  తిరిగి libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
 Sample a vector of ring elements from a centered binomial distribution.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.sample_ring_element_cbd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- ETA2_RANDOMNESS_SIZE= 128
- ETA2= 2
*/
స్థిర KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_bf(
  స్థిరరాశి Eurydice_arr_fa0 *prf_ఆదానం,
  uint8_t domain_separator,
  Eurydice_arr_bb0 *error_1
)
{
  Eurydice_arr_fd prf_inputs;
  Eurydice_arr_fa0 repeat_వ్యక్తీకరణ[3U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    repeat_వ్యక్తీకరణ[i] =
      core_array__core__clone__Clone_for__T__N___clone((కొలత_t)33U,
        prf_ఆదానం,
        uint8_t,
        Eurydice_arr_fa0);
  }
  జ్ఞాపకం_నకలు(prf_inputs.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)3U * పరిమాణం (Eurydice_arr_fa0));
  domain_separator = libcrux_ml_kem_utils_prf_ఆదానం_inc_78(&prf_inputs, domain_separator);
  Eurydice_arr_58 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(&prf_inputs);
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_ద్విపద_distribution_66(Eurydice_array_గమ్యం_ముక్క_shared_78(&prf_outputs.దత్తాంశం[i0]));
    error_1->దత్తాంశం[i0] = uu____0;
  }
  తిరిగి domain_separator;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 128
*/
స్థిర అంతఃవరుస Eurydice_arr_89
libcrux_ml_kem_hash_functions_portable_PRF_ec(Eurydice_borrow_ముక్క_u8 ఆదానం)
{
  Eurydice_arr_89 digest = { .దత్తాంశం = { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_గమ్యం_ముక్క_mut_78(&digest), ఆదానం);
  తిరిగి digest;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF_4a
with const generics
- K= 3
- LEN= 128
*/
స్థిర అంతఃవరుస Eurydice_arr_89
libcrux_ml_kem_hash_functions_portable_PRF_4a_3b0(Eurydice_borrow_ముక్క_u8 ఆదానం)
{
  తిరిగి libcrux_ml_kem_hash_functions_portable_PRF_ec(ఆదానం);
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::matrix::compute_vector_u::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_vector_u.call_mut_a8
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_మాతృక_compute_సదిశ_u_call_mut_a8_68(శూన్య **_, కొలత_t tupled_వాదనలు)
{
  తిరిగి libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_polynomial_కూడు_error_reduce_ea(
  Eurydice_arr_9e *myself,
  స్థిరరాశి Eurydice_arr_9e *error
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_d6
    coefficient_సాధారణ_form =
      libcrux_ml_kem_సదిశ_portable_montgomery_multiply_by_constant_b8(myself->దత్తాంశం[j],
        1441);
    Eurydice_arr_d6
    కూడిక = libcrux_ml_kem_సదిశ_portable_కూడు_b8(coefficient_సాధారణ_form, &error->దత్తాంశం[j]);
    Eurydice_arr_d6 red = libcrux_ml_kem_సదిశ_portable_barrett_reduce_b8(కూడిక);
    myself->దత్తాంశం[j] = red;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_polynomial_కూడు_error_reduce_d6_ea(
  Eurydice_arr_9e *self,
  స్థిరరాశి Eurydice_arr_9e *error
)
{
  libcrux_ml_kem_polynomial_కూడు_error_reduce_ea(self, error);
}

/**
 Compute u := InvertNTT(Aᵀ ◦ r̂) + e₁
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_vector_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_మాతృక_compute_సదిశ_u_68(
  స్థిరరాశి Eurydice_arr_c10 *a_as_ntt,
  స్థిరరాశి Eurydice_arr_bb0 *r_as_ntt,
  స్థిరరాశి Eurydice_arr_bb0 *error_1
)
{
  Eurydice_arr_bb0 arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_struct.దత్తాంశం[i] = libcrux_ml_kem_మాతృక_compute_సదిశ_u_call_mut_a8_68(&lvalue, i);
  }
  Eurydice_arr_bb0 ఫలితం = arr_struct;
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < (కొలత_t)3U; i0++)
  {
    కొలత_t i1 = i0;
    స్థిరరాశి Eurydice_arr_bb0 *అడ్డువరుస = &a_as_ntt->దత్తాంశం[i1];
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
    {
      కొలత_t j = i;
      స్థిరరాశి Eurydice_arr_9e *a_element = &అడ్డువరుస->దత్తాంశం[j];
      Eurydice_arr_9e
      లబ్ధం = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(a_element, &r_as_ntt->దత్తాంశం[j]);
      libcrux_ml_kem_polynomial_కూడు_గమ్యం_ring_element_d6_68(&ఫలితం.దత్తాంశం[i1], &లబ్ధం);
    }
    libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&ఫలితం.దత్తాంశం[i1]);
    libcrux_ml_kem_polynomial_కూడు_error_reduce_d6_ea(&ఫలితం.దత్తాంశం[i1], &error_1->దత్తాంశం[i1]);
  }
  తిరిగి ఫలితం;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 10
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_compress_compress_ef(Eurydice_arr_d6 a)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_సదిశ_portable_compress_compress_ciphertext_coefficient((uint8_t)10,
          libcrux_secrets_int_as_u16_f5(a.దత్తాంశం[i0])));
    a.దత్తాంశం[i0] = uu____0;
  }
  తిరిగి a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 10
*/
స్థిర అంతఃవరుస Eurydice_arr_d6 libcrux_ml_kem_సదిశ_portable_compress_b8_ef(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_compress_compress_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- OUT_LEN= 320
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_b0
libcrux_ml_kem_serialize_compress_then_serialize_10_e1(స్థిరరాశి Eurydice_arr_9e *re)
{
  Eurydice_arr_b0 serialized = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    coefficient =
      libcrux_ml_kem_సదిశ_portable_compress_b8_ef(libcrux_ml_kem_serialize_గమ్యం_unsigned_క్షేత్రం_modulus_ea(re->దత్తాంశం[i0]));
    Eurydice_arr_fc బైట్లు = libcrux_ml_kem_సదిశ_portable_serialize_10_b8(coefficient);
    Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d413(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = (కొలత_t)20U * i0,
            .చివర = (కొలత_t)20U * i0 + (కొలత_t)20U
          }
        )),
      Eurydice_array_గమ్యం_ముక్క_shared_8f(&బైట్లు),
      uint8_t);
  }
  తిరిగి serialized;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
- OUT_LEN= 320
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_b0
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_f7(స్థిరరాశి Eurydice_arr_9e *re)
{
  తిరిగి libcrux_ml_kem_serialize_compress_then_serialize_10_e1(re);
}

/**
 Call [`compress_then_serialize_ring_element_u`] on each ring element.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.compress_then_serialize_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- OUT_LEN= 960
- COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cpa_compress_then_serialize_u_21(
  Eurydice_arr_bb0 ఆదానం,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_9e re = ఆదానం.దత్తాంశం[i0];
    Eurydice_mut_borrow_ముక్క_u8
    uu____0 =
      Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * ((కొలత_t)960U / (కొలత_t)3U),
            .చివర = (i0 + (కొలత_t)1U) * ((కొలత_t)960U / (కొలత_t)3U)
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_b0
    lvalue = libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_f7(&re);
    Eurydice_ముక్క_copy(uu____0, Eurydice_array_గమ్యం_ముక్క_shared_56(&lvalue), uint8_t);
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- C1_LEN= 960
- U_COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE tuple_c6
libcrux_ml_kem_ind_cpa_encrypt_c1_87(
  Eurydice_borrow_ముక్క_u8 randomness,
  స్థిరరాశి Eurydice_arr_c10 *మాతృక,
  Eurydice_mut_borrow_ముక్క_u8 ciphertext
)
{
  Eurydice_arr_fa0 prf_ఆదానం = libcrux_ml_kem_utils_into_padded_array_29(randomness);
  Eurydice_arr_bb0 arr_struct0;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_struct0.దత్తాంశం[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_87(&lvalue, i);
  }
  Eurydice_arr_bb0 r_as_ntt = arr_struct0;
  uint8_t
  domain_separator0 =
    libcrux_ml_kem_ind_cpa_sample_సదిశ_cbd_then_ntt_bf(&r_as_ntt,
      &prf_ఆదానం,
      0U);
  Eurydice_arr_bb0 arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_struct.దత్తాంశం[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_87(&lvalue, i);
  }
  Eurydice_arr_bb0 error_1 = arr_struct;
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_bf(&prf_ఆదానం,
      domain_separator0,
      &error_1);
  prf_ఆదానం.దత్తాంశం[32U] = domain_separator;
  Eurydice_arr_89
  prf_output =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b0(Eurydice_array_గమ్యం_ముక్క_shared_b5(&prf_ఆదానం));
  Eurydice_arr_9e
  error_2 =
    libcrux_ml_kem_sampling_sample_from_ద్విపద_distribution_66(Eurydice_array_గమ్యం_ముక్క_shared_78(&prf_output));
  Eurydice_arr_bb0 u = libcrux_ml_kem_మాతృక_compute_సదిశ_u_68(మాతృక, &r_as_ntt, &error_1);
  libcrux_ml_kem_ind_cpa_compress_then_serialize_u_21(u, ciphertext);
  తిరిగి (KRML_CLITERAL(tuple_c6){ .fst = r_as_ntt, .snd = error_2 });
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_సందేశం_ea(
  స్థిరరాశి Eurydice_arr_ec *serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)16U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    coefficient_compressed =
      libcrux_ml_kem_సదిశ_portable_deserialize_1_b8(Eurydice_array_గమ్యం_subslice_shared_d4(serialized,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ప్రారంభం = (కొలత_t)2U * i0,
              .చివర = (కొలత_t)2U * i0 + (కొలత_t)2U
            }
          )));
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_సదిశ_portable_decompress_1_b8(coefficient_compressed);
    re.దత్తాంశం[i0] = uu____0;
  }
  తిరిగి re;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_కూడు_సందేశం_error_reduce_ea(
  స్థిరరాశి Eurydice_arr_9e *myself,
  స్థిరరాశి Eurydice_arr_9e *సందేశం_2,
  Eurydice_arr_9e ఫలితం
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    coefficient_సాధారణ_form =
      libcrux_ml_kem_సదిశ_portable_montgomery_multiply_by_constant_b8(ఫలితం.దత్తాంశం[i0],
        1441);
    Eurydice_arr_d6
    sum1 = libcrux_ml_kem_సదిశ_portable_కూడు_b8(myself->దత్తాంశం[i0], &సందేశం_2->దత్తాంశం[i0]);
    Eurydice_arr_d6 sum2 = libcrux_ml_kem_సదిశ_portable_కూడు_b8(coefficient_సాధారణ_form, &sum1);
    Eurydice_arr_d6 red = libcrux_ml_kem_సదిశ_portable_barrett_reduce_b8(sum2);
    ఫలితం.దత్తాంశం[i0] = red;
  }
  తిరిగి ఫలితం;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_కూడు_సందేశం_error_reduce_d6_ea(
  స్థిరరాశి Eurydice_arr_9e *self,
  స్థిరరాశి Eurydice_arr_9e *సందేశం_2,
  Eurydice_arr_9e ఫలితం
)
{
  తిరిగి libcrux_ml_kem_polynomial_కూడు_సందేశం_error_reduce_ea(self, సందేశం_2, ఫలితం);
}

/**
 Compute InverseNTT(tᵀ ◦ r̂) + e₂ + message
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_మాతృక_compute_ring_element_v_68(
  స్థిరరాశి Eurydice_arr_bb0 *t_as_ntt,
  స్థిరరాశి Eurydice_arr_bb0 *r_as_ntt,
  స్థిరరాశి Eurydice_arr_9e *error_2,
  స్థిరరాశి Eurydice_arr_9e *సందేశం_2
)
{
  Eurydice_arr_9e ఫలితం = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_9e
    లబ్ధం =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&t_as_ntt->దత్తాంశం[i0],
        &r_as_ntt->దత్తాంశం[i0]);
    libcrux_ml_kem_polynomial_కూడు_గమ్యం_ring_element_d6_68(&ఫలితం, &లబ్ధం);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&ఫలితం);
  తిరిగి libcrux_ml_kem_polynomial_కూడు_సందేశం_error_reduce_d6_ea(error_2, సందేశం_2, ఫలితం);
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 4
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_సదిశ_portable_compress_compress_d1(Eurydice_arr_d6 a)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_సదిశ_TRAITS_క్షేత్రం_ELEMENTS_లోపల_సదిశ; i++)
  {
    కొలత_t i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_సదిశ_portable_compress_compress_ciphertext_coefficient((uint8_t)4,
          libcrux_secrets_int_as_u16_f5(a.దత్తాంశం[i0])));
    a.దత్తాంశం[i0] = uu____0;
  }
  తిరిగి a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 4
*/
స్థిర అంతఃవరుస Eurydice_arr_d6 libcrux_ml_kem_సదిశ_portable_compress_b8_d1(Eurydice_arr_d6 a)
{
  తిరిగి libcrux_ml_kem_సదిశ_portable_compress_compress_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_serialize_compress_then_serialize_4_ea(
  Eurydice_arr_9e re,
  Eurydice_mut_borrow_ముక్క_u8 serialized
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    coefficient =
      libcrux_ml_kem_సదిశ_portable_compress_b8_d1(libcrux_ml_kem_serialize_గమ్యం_unsigned_క్షేత్రం_modulus_ea(re.దత్తాంశం[i0]));
    Eurydice_array_u8x8 బైట్లు = libcrux_ml_kem_సదిశ_portable_serialize_4_b8(coefficient);
    Eurydice_ముక్క_copy(Eurydice_ముక్క_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = (కొలత_t)8U * i0,
            .చివర = (కొలత_t)8U * i0 + (కొలత_t)8U
          }
        )),
      Eurydice_array_గమ్యం_ముక్క_shared_6e(&బైట్లు),
      uint8_t);
  }
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- COMPRESSION_FACTOR= 4
- OUT_LEN= 128
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_v_30(
  Eurydice_arr_9e re,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  libcrux_ml_kem_serialize_compress_then_serialize_4_ea(re, బహిర్గతం);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- V_COMPRESSION_FACTOR= 4
- C2_LEN= 128
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cpa_encrypt_c2_30(
  స్థిరరాశి Eurydice_arr_bb0 *t_as_ntt,
  స్థిరరాశి Eurydice_arr_bb0 *r_as_ntt,
  స్థిరరాశి Eurydice_arr_9e *error_2,
  స్థిరరాశి Eurydice_arr_ec *సందేశం_2,
  Eurydice_mut_borrow_ముక్క_u8 ciphertext
)
{
  Eurydice_arr_9e
  సందేశం_as_ring_element =
    libcrux_ml_kem_serialize_deserialize_then_decompress_సందేశం_ea(సందేశం_2);
  Eurydice_arr_9e
  v =
    libcrux_ml_kem_మాతృక_compute_ring_element_v_68(t_as_ntt,
      r_as_ntt,
      error_2,
      &సందేశం_as_ring_element);
  libcrux_ml_kem_serialize_compress_then_serialize_ring_element_v_30(v, ciphertext);
}

/**
 This function implements <strong>Algorithm 13</strong> of the
 NIST FIPS 203 specification; this is the Kyber CPA-PKE encryption algorithm.

 Algorithm 13 is reproduced below:

 ```plaintext
 Input: encryption key ekₚₖₑ ∈ 𝔹^{384k+32}.
 Input: message m ∈ 𝔹^{32}.
 Input: encryption randomness r ∈ 𝔹^{32}.
 Output: ciphertext c ∈ 𝔹^{32(dᵤk + dᵥ)}.

 N ← 0
 t̂ ← ByteDecode₁₂(ekₚₖₑ[0:384k])
 ρ ← ekₚₖₑ[384k: 384k + 32]
 for (i ← 0; i < k; i++)
     for(j ← 0; j < k; j++)
         Â[i,j] ← SampleNTT(XOF(ρ, i, j))
     end for
 end for
 for(i ← 0; i < k; i++)
     r[i] ← SamplePolyCBD_{η₁}(PRF_{η₁}(r,N))
     N ← N + 1
 end for
 for(i ← 0; i < k; i++)
     e₁[i] ← SamplePolyCBD_{η₂}(PRF_{η₂}(r,N))
     N ← N + 1
 end for
 e₂ ← SamplePolyCBD_{η₂}(PRF_{η₂}(r,N))
 r̂ ← NTT(r)
 u ← NTT-¹(Âᵀ ◦ r̂) + e₁
 μ ← Decompress₁(ByteDecode₁(m)))
 v ← NTT-¹(t̂ᵀ ◦ rˆ) + e₂ + μ
 c₁ ← ByteEncode_{dᵤ}(Compress_{dᵤ}(u))
 c₂ ← ByteEncode_{dᵥ}(Compress_{dᵥ}(v))
 return c ← (c₁ ‖ c₂)
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_unpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_LEN= 960
- C2_LEN= 128
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_2b
libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(
  స్థిరరాశి libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51 *ప్రజా_కీలకం,
  స్థిరరాశి Eurydice_arr_ec *సందేశం_2,
  Eurydice_borrow_ముక్క_u8 randomness
)
{
  Eurydice_arr_2b ciphertext = { .దత్తాంశం = { 0U } };
  tuple_c6
  uu____0 =
    libcrux_ml_kem_ind_cpa_encrypt_c1_87(randomness,
      &ప్రజా_కీలకం->A,
      Eurydice_array_గమ్యం_subslice_mut_d414(&ciphertext,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = (కొలత_t)0U, .చివర = (కొలత_t)960U })));
  Eurydice_arr_bb0 r_as_ntt = uu____0.fst;
  Eurydice_arr_9e error_2 = uu____0.snd;
  libcrux_ml_kem_ind_cpa_encrypt_c2_30(&ప్రజా_కీలకం->t_as_ntt,
    &r_as_ntt,
    &error_2,
    సందేశం_2,
    Eurydice_array_గమ్యం_subslice_from_mut_5f3(&ciphertext, (కొలత_t)960U));
  తిరిగి ciphertext;
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_LEN= 960
- C2_LEN= 128
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_2b
libcrux_ml_kem_ind_cpa_encrypt_d5(
  Eurydice_borrow_ముక్క_u8 ప్రజా_కీలకం,
  స్థిరరాశి Eurydice_arr_ec *సందేశం_2,
  Eurydice_borrow_ముక్క_u8 randomness
)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51
  unpacked_ప్రజా_కీలకం = libcrux_ml_kem_ind_cpa_build_unpacked_ప్రజా_కీలకం_05(ప్రజా_కీలకం);
  తిరిగి libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&unpacked_ప్రజా_కీలకం, సందేశం_2, randomness);
}

/**
This function found in impl {libcrux_ml_kem::variant::Variant for libcrux_ml_kem::variant::MlKem}
*/
/**
A monomorphic instance of libcrux_ml_kem.variant.kdf_39
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_variant_kdf_39_52(
  Eurydice_borrow_ముక్క_u8 shared_secret,
  స్థిరరాశి Eurydice_arr_2b *_
)
{
  Eurydice_arr_ec బహిర్గతం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_01(&బహిర్గతం), shared_secret, uint8_t);
  తిరిగి బహిర్గతం;
}

/**
 This code verifies on some machines, runs out of memory on others
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.decapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_decapsulate_fd(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  Eurydice_borrow_ముక్క_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_వ్యక్తిగత_కీలకం_64(Eurydice_array_గమ్యం_ముక్క_shared_51(వ్యక్తిగత_కీలకం));
  Eurydice_borrow_ముక్క_u8 ind_cpa_secret_కీలకం = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 ind_cpa_ప్రజా_కీలకం = uu____0.snd;
  Eurydice_borrow_ముక్క_u8 ind_cpa_ప్రజా_కీలకం_hash = uu____0.thd;
  Eurydice_borrow_ముక్క_u8 implicit_rejection_విలువ = uu____0.f3;
  Eurydice_arr_ec decrypted = libcrux_ml_kem_ind_cpa_decrypt_01(ind_cpa_secret_కీలకం, ciphertext);
  Eurydice_arr_c7
  గమ్యం_hash0 =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_గమ్యం_ముక్క_shared_01(&decrypted));
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_from_mut_5f1(&గమ్యం_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత),
    ind_cpa_ప్రజా_కీలకం_hash,
    uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_గమ్యం_ముక్క_shared_17(&గమ్యం_hash0));
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 shared_secret0 = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_af గమ్యం_hash = libcrux_ml_kem_utils_into_padded_array_66(implicit_rejection_విలువ);
  Eurydice_mut_borrow_ముక్క_u8
  uu____2 =
    Eurydice_array_గమ్యం_subslice_from_mut_5f2(&గమ్యం_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత);
  Eurydice_ముక్క_copy(uu____2, libcrux_ml_kem_types_as_ref_c1_52(ciphertext), uint8_t);
  Eurydice_arr_ec
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_array_గమ్యం_ముక్క_shared_81(&గమ్యం_hash));
  Eurydice_arr_2b
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_d5(ind_cpa_ప్రజా_కీలకం,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_ముక్క_u8
  uu____3 = Eurydice_array_గమ్యం_ముక్క_shared_01(&implicit_rejection_shared_secret);
  Eurydice_arr_ec
  implicit_rejection_shared_secret0 =
    libcrux_ml_kem_variant_kdf_39_52(uu____3,
      libcrux_ml_kem_types_as_ముక్క_a9_52(ciphertext));
  Eurydice_arr_ec
  shared_secret =
    libcrux_ml_kem_variant_kdf_39_52(shared_secret0,
      libcrux_ml_kem_types_as_ముక్క_a9_52(ciphertext));
  Eurydice_borrow_ముక్క_u8 uu____4 = libcrux_ml_kem_types_as_ref_c1_52(ciphertext);
  తిరిగి
    libcrux_ml_kem_constant_సమయం_ops_compare_ciphertexts_select_shared_secret_లోపల_constant_సమయం(uu____4,
      Eurydice_array_గమ్యం_ముక్క_shared_06(&expected_ciphertext),
      Eurydice_array_గమ్యం_ముక్క_shared_01(&shared_secret),
      Eurydice_array_గమ్యం_ముక్క_shared_01(&implicit_rejection_shared_secret0));
}

/**
 Portable decapsulate
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.decapsulate
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
స్థిర అంతఃవరుస Eurydice_arr_ec
libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_19(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  తిరిగి libcrux_ml_kem_ind_cca_decapsulate_fd(వ్యక్తిగత_కీలకం, ciphertext);
}

/**
 Decapsulate ML-KEM 768

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
*/
స్థిర అంతఃవరుస Eurydice_arr_ec
libcrux_ml_kem_mlkem768_portable_decapsulate(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  తిరిగి libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_19(వ్యక్తిగత_కీలకం, ciphertext);
}

/**
This function found in impl {libcrux_ml_kem::variant::Variant for libcrux_ml_kem::variant::MlKem}
*/
/**
A monomorphic instance of libcrux_ml_kem.variant.entropy_preprocess_39
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_variant_entropy_preprocess_39_13(Eurydice_borrow_ముక్క_u8 randomness)
{
  Eurydice_arr_ec బహిర్గతం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_01(&బహిర్గతం), randomness, uint8_t);
  తిరిగి బహిర్గతం;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.H_4a
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_borrow_ముక్క_u8 ఆదానం)
{
  తిరిగి libcrux_ml_kem_hash_functions_portable_H(ఆదానం);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.encapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_encapsulate_99(
  స్థిరరాశి Eurydice_arr_5f *ప్రజా_కీలకం,
  స్థిరరాశి Eurydice_arr_ec *randomness
)
{
  Eurydice_arr_ec
  randomness0 =
    libcrux_ml_kem_variant_entropy_preprocess_39_13(Eurydice_array_గమ్యం_ముక్క_shared_01(randomness));
  Eurydice_arr_c7
  గమ్యం_hash =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_గమ్యం_ముక్క_shared_01(&randomness0));
  Eurydice_mut_borrow_ముక్క_u8
  uu____0 =
    Eurydice_array_గమ్యం_subslice_from_mut_5f1(&గమ్యం_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_కొలత);
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_ec
  lvalue =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_గమ్యం_ముక్క_shared_ff(libcrux_ml_kem_types_as_ముక్క_e6_3d(ప్రజా_కీలకం)));
  Eurydice_ముక్క_copy(uu____0, Eurydice_array_గమ్యం_ముక్క_shared_01(&lvalue), uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_గమ్యం_ముక్క_shared_17(&గమ్యం_hash));
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_2b
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_d5(Eurydice_array_గమ్యం_ముక్క_shared_ff(libcrux_ml_kem_types_as_ముక్క_e6_3d(ప్రజా_కీలకం)),
      &randomness0,
      pseudorandomness);
  Eurydice_arr_2b uu____2 = libcrux_ml_kem_types_from_19_52(ciphertext);
  తిరిగి
    (
      KRML_CLITERAL(tuple_f4){
        .fst = uu____2,
        .snd = libcrux_ml_kem_variant_kdf_39_52(shared_secret, &ciphertext)
      }
    );
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.encapsulate
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
స్థిర అంతఃవరుస tuple_f4
libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_26(
  స్థిరరాశి Eurydice_arr_5f *ప్రజా_కీలకం,
  స్థిరరాశి Eurydice_arr_ec *randomness
)
{
  తిరిగి libcrux_ml_kem_ind_cca_encapsulate_99(ప్రజా_కీలకం, randomness);
}

/**
 Encapsulate ML-KEM 768

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an [`MlKem768PublicKey`] and [`SHARED_SECRET_SIZE`]
 bytes of `randomness`.
*/
స్థిర అంతఃవరుస tuple_f4
libcrux_ml_kem_mlkem768_portable_encapsulate(
  స్థిరరాశి Eurydice_arr_5f *ప్రజా_కీలకం,
  Eurydice_arr_ec randomness
)
{
  తిరిగి libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_26(ప్రజా_కీలకం, &randomness);
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPrivateKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.default_70
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_bb0 libcrux_ml_kem_ind_cpa_unpacked_default_70_68(శూన్య)
{
  Eurydice_arr_bb0 lit;
  Eurydice_arr_9e repeat_వ్యక్తీకరణ[3U];
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    repeat_వ్యక్తీకరణ[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  జ్ఞాపకం_నకలు(lit.దత్తాంశం, repeat_వ్యక్తీకరణ, (కొలత_t)3U * పరిమాణం (Eurydice_arr_9e));
  తిరిగి lit;
}

/**
This function found in impl {libcrux_ml_kem::variant::Variant for libcrux_ml_kem::variant::MlKem}
*/
/**
A monomorphic instance of libcrux_ml_kem.variant.cpa_keygen_seed_39
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_c7
libcrux_ml_kem_variant_cpa_keygen_విత్తనం_39_13(Eurydice_borrow_ముక్క_u8 కీలకం_generation_విత్తనం)
{
  Eurydice_arr_fa0 విత్తనం = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d412(&విత్తనం,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)0U,
          .చివర = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_కీలకం_GENERATION_విత్తనం_కొలత
        }
      )),
    కీలకం_generation_విత్తనం,
    uint8_t);
  విత్తనం.దత్తాంశం[LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_కీలకం_GENERATION_విత్తనం_కొలత] = (uint8_t)(కొలత_t)3U;
  తిరిగి
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_గమ్యం_ముక్క_shared_b5(&విత్తనం));
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@3]> for libcrux_ml_kem::ind_cpa::generate_keypair_unpacked::closure<Vector, Hasher, Scheme, K, ETA1, ETA1_RANDOMNESS_SIZE>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3, TraitClause@4, TraitClause@5]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.generate_keypair_unpacked.call_mut_73
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_39(శూన్య **_, కొలత_t tupled_వాదనలు)
{
  తిరిగి libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.to_standard_domain
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_polynomial_గమ్యం_standard_domain_ea(Eurydice_arr_d6 సదిశ)
{
  తిరిగి
    libcrux_ml_kem_సదిశ_portable_montgomery_multiply_by_constant_b8(సదిశ,
      LIBCRUX_ML_KEM_సదిశ_TRAITS_MONTGOMERY_R_SQUARED_MOD_క్షేత్రం_MODULUS);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_standard_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_polynomial_కూడు_standard_error_reduce_ea(
  Eurydice_arr_9e *myself,
  స్థిరరాశి Eurydice_arr_9e *error
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t j = i;
    Eurydice_arr_d6
    coefficient_సాధారణ_form = libcrux_ml_kem_polynomial_గమ్యం_standard_domain_ea(myself->దత్తాంశం[j]);
    Eurydice_arr_d6
    కూడిక = libcrux_ml_kem_సదిశ_portable_కూడు_b8(coefficient_సాధారణ_form, &error->దత్తాంశం[j]);
    Eurydice_arr_d6 red = libcrux_ml_kem_సదిశ_portable_barrett_reduce_b8(కూడిక);
    myself->దత్తాంశం[j] = red;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_standard_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_polynomial_కూడు_standard_error_reduce_d6_ea(
  Eurydice_arr_9e *self,
  స్థిరరాశి Eurydice_arr_9e *error
)
{
  libcrux_ml_kem_polynomial_కూడు_standard_error_reduce_ea(self, error);
}

/**
 Compute Â ◦ ŝ + ê
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_As_plus_e
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_మాతృక_compute_As_plus_e_68(
  Eurydice_arr_bb0 *t_as_ntt,
  స్థిరరాశి Eurydice_arr_c10 *మాతృక_A,
  స్థిరరాశి Eurydice_arr_bb0 *s_as_ntt,
  స్థిరరాశి Eurydice_arr_bb0 *error_as_ntt
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    స్థిరరాశి Eurydice_arr_bb0 *అడ్డువరుస = &మాతృక_A->దత్తాంశం[i0];
    Eurydice_arr_9e uu____0 = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    t_as_ntt->దత్తాంశం[i0] = uu____0;
    కొరకు (కొలత_t i1 = (కొలత_t)0U; i1 < (కొలత_t)3U; i1++)
    {
      కొలత_t j = i1;
      స్థిరరాశి Eurydice_arr_9e *మాతృక_element = &అడ్డువరుస->దత్తాంశం[j];
      Eurydice_arr_9e
      లబ్ధం = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(మాతృక_element, &s_as_ntt->దత్తాంశం[j]);
      libcrux_ml_kem_polynomial_కూడు_గమ్యం_ring_element_d6_68(&t_as_ntt->దత్తాంశం[i0], &లబ్ధం);
    }
    libcrux_ml_kem_polynomial_కూడు_standard_error_reduce_d6_ea(&t_as_ntt->దత్తాంశం[i0],
      &error_as_ntt->దత్తాంశం[i0]);
  }
}

/**
 This function implements most of <strong>Algorithm 12</strong> of the
 NIST FIPS 203 specification; this is the Kyber CPA-PKE key generation algorithm.

 We say "most of" since Algorithm 12 samples the required randomness within
 the function itself, whereas this implementation expects it to be provided
 through the `key_generation_seed` parameter.

 Algorithm 12 is reproduced below:

 ```plaintext
 Output: encryption key ekₚₖₑ ∈ 𝔹^{384k+32}.
 Output: decryption key dkₚₖₑ ∈ 𝔹^{384k}.

 d ←$ B
 (ρ,σ) ← G(d)
 N ← 0
 for (i ← 0; i < k; i++)
     for(j ← 0; j < k; j++)
         Â[i,j] ← SampleNTT(XOF(ρ, i, j))
     end for
 end for
 for(i ← 0; i < k; i++)
     s[i] ← SamplePolyCBD_{η₁}(PRF_{η₁}(σ,N))
     N ← N + 1
 end for
 for(i ← 0; i < k; i++)
     e[i] ← SamplePolyCBD_{η₂}(PRF_{η₂}(σ,N))
     N ← N + 1
 end for
 ŝ ← NTT(s)
 ê ← NTT(e)
 t̂ ← Â◦ŝ + ê
 ekₚₖₑ ← ByteEncode₁₂(t̂) ‖ ρ
 dkₚₖₑ ← ByteEncode₁₂(ŝ)
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.generate_keypair_unpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(
  Eurydice_borrow_ముక్క_u8 కీలకం_generation_విత్తనం,
  Eurydice_arr_bb0 *వ్యక్తిగత_కీలకం,
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51 *ప్రజా_కీలకం
)
{
  Eurydice_arr_c7 hashed = libcrux_ml_kem_variant_cpa_keygen_విత్తనం_39_13(కీలకం_generation_విత్తనం);
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_17(&hashed),
      (కొలత_t)32U,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_A = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_secret_and_error = uu____0.snd;
  Eurydice_arr_c10 *uu____1 = &ప్రజా_కీలకం->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31 lvalue0 = libcrux_ml_kem_utils_into_padded_array_de(విత్తనం_for_A);
  libcrux_ml_kem_మాతృక_sample_మాతృక_A_91(uu____1, &lvalue0, true);
  Eurydice_arr_fa0
  prf_ఆదానం = libcrux_ml_kem_utils_into_padded_array_29(విత్తనం_for_secret_and_error);
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_సదిశ_cbd_then_ntt_bf(వ్యక్తిగత_కీలకం,
      &prf_ఆదానం,
      0U);
  Eurydice_arr_bb0 arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_struct.దత్తాంశం[i] =
      libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_39(&lvalue,
        i);
  }
  Eurydice_arr_bb0 error_as_ntt = arr_struct;
  libcrux_ml_kem_ind_cpa_sample_సదిశ_cbd_then_ntt_bf(&error_as_ntt,
    &prf_ఆదానం,
    domain_separator);
  libcrux_ml_kem_మాతృక_compute_As_plus_e_68(&ప్రజా_కీలకం->t_as_ntt,
    &ప్రజా_కీలకం->A,
    &వ్యక్తిగత_కీలకం[0U],
    &error_as_ntt);
  Eurydice_arr_ec arr;
  జ్ఞాపకం_నకలు(arr.దత్తాంశం, విత్తనం_for_A.ptr, (కొలత_t)32U * పరిమాణం (uint8_t));
  Eurydice_arr_ec
  uu____2 =
    core_ఫలితం_unwrap_26_39((
        KRML_CLITERAL(core_ఫలితం_ఫలితం_07){ .ట్యాగ్ = core_ఫలితం_Ok, .val = { .case_Ok = arr } }
      ));
  ప్రజా_కీలకం->విత్తనం_for_A = uu____2;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.serialize_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర KRML_MUSTINLINE Eurydice_arr_b20
libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(స్థిరరాశి Eurydice_arr_9e *re)
{
  Eurydice_arr_b20 serialized = { .దత్తాంశం = { 0U } };
  కొరకు (కొలత_t i = (కొలత_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_లోపల_RING_ELEMENT; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_d6
    coefficient = libcrux_ml_kem_serialize_గమ్యం_unsigned_క్షేత్రం_modulus_ea(re->దత్తాంశం[i0]);
    Eurydice_arr_94 బైట్లు = libcrux_ml_kem_సదిశ_portable_serialize_12_b8(coefficient);
    Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d415(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = (కొలత_t)24U * i0,
            .చివర = (కొలత_t)24U * i0 + (కొలత_t)24U
          }
        )),
      Eurydice_array_గమ్యం_ముక్క_shared_ed(&బైట్లు),
      uint8_t);
  }
  తిరిగి serialized;
}

/**
 Call [`serialize_uncompressed_ring_element`] for each ring element.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_vector
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cpa_serialize_సదిశ_68(
  స్థిరరాశి Eurydice_arr_bb0 *కీలకం,
  Eurydice_mut_borrow_ముక్క_u8 బహిర్గతం
)
{
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    కొలత_t i0 = i;
    Eurydice_arr_9e re = కీలకం->దత్తాంశం[i0];
    Eurydice_mut_borrow_ముక్క_u8
    uu____0 =
      Eurydice_ముక్క_subslice_mut_c8(బహిర్గతం,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = i0 * LIBCRUX_ML_KEM_CONSTANTS_బైట్లు_చొప్పున_RING_ELEMENT,
            .చివర = (i0 + (కొలత_t)1U) * LIBCRUX_ML_KEM_CONSTANTS_బైట్లు_చొప్పున_RING_ELEMENT
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_b20 lvalue = libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(&re);
    Eurydice_ముక్క_copy(uu____0, Eurydice_array_గమ్యం_ముక్క_shared_a9(&lvalue), uint8_t);
  }
}

/**
 Concatenate `t` and `ρ` into the public key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_public_key_mut
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cpa_serialize_ప్రజా_కీలకం_mut_b6(
  స్థిరరాశి Eurydice_arr_bb0 *t_as_ntt,
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_సదిశ_68(t_as_ntt,
    Eurydice_array_గమ్యం_subslice_mut_d416(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)0U,
          .చివర = libcrux_ml_kem_constants_ranked_బైట్లు_చొప్పున_ring_element((కొలత_t)3U)
        }
      )));
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_from_mut_5f4(serialized,
      libcrux_ml_kem_constants_ranked_బైట్లు_చొప్పున_ring_element((కొలత_t)3U)),
    విత్తనం_for_a,
    uint8_t);
}

/**
 Concatenate `t` and `ρ` into the public key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cpa_serialize_ప్రజా_కీలకం_b6(
  స్థిరరాశి Eurydice_arr_bb0 *t_as_ntt,
  Eurydice_borrow_ముక్క_u8 విత్తనం_for_a
)
{
  Eurydice_arr_5f ప్రజా_కీలకం_serialized = { .దత్తాంశం = { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_ప్రజా_కీలకం_mut_b6(t_as_ntt,
    విత్తనం_for_a,
    &ప్రజా_కీలకం_serialized);
  తిరిగి ప్రజా_కీలకం_serialized;
}

/**
 Serialize the secret key from the unpacked key pair generation.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_unpacked_secret_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PRIVATE_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర అంతఃవరుస libcrux_ml_kem_utils_extraction_helper_Keypair768
libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_కీలకం_30(
  స్థిరరాశి libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51 *ప్రజా_కీలకం,
  స్థిరరాశి Eurydice_arr_bb0 *వ్యక్తిగత_కీలకం
)
{
  Eurydice_arr_5f
  ప్రజా_కీలకం_serialized =
    libcrux_ml_kem_ind_cpa_serialize_ప్రజా_కీలకం_b6(&ప్రజా_కీలకం->t_as_ntt,
      Eurydice_array_గమ్యం_ముక్క_shared_01(&ప్రజా_కీలకం->విత్తనం_for_A));
  Eurydice_arr_0e secret_కీలకం_serialized = { .దత్తాంశం = { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_సదిశ_68(వ్యక్తిగత_కీలకం,
    Eurydice_array_గమ్యం_ముక్క_mut_f4(&secret_కీలకం_serialized));
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_kem_utils_extraction_helper_Keypair768){
        .fst = secret_కీలకం_serialized,
        .snd = ప్రజా_కీలకం_serialized
      }
    );
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.generate_keypair
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- PRIVATE_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE libcrux_ml_kem_utils_extraction_helper_Keypair768
libcrux_ml_kem_ind_cpa_generate_keypair_30(Eurydice_borrow_ముక్క_u8 కీలకం_generation_విత్తనం)
{
  Eurydice_arr_bb0 వ్యక్తిగత_కీలకం = libcrux_ml_kem_ind_cpa_unpacked_default_70_68();
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51
  ప్రజా_కీలకం = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68();
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(కీలకం_generation_విత్తనం,
    &వ్యక్తిగత_కీలకం,
    &ప్రజా_కీలకం);
  తిరిగి libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_కీలకం_30(&ప్రజా_కీలకం, &వ్యక్తిగత_కీలకం);
}

/**
 Serialize the secret key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.serialize_kem_secret_key_mut
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SERIALIZED_KEY_LEN= 2400
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_serialize_kem_secret_కీలకం_mut_52(
  Eurydice_borrow_ముక్క_u8 వ్యక్తిగత_కీలకం,
  Eurydice_borrow_ముక్క_u8 ప్రజా_కీలకం,
  Eurydice_borrow_ముక్క_u8 implicit_rejection_విలువ,
  Eurydice_arr_7d *serialized
)
{
  కొలత_t సూచిక = (కొలత_t)0U;
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = సూచిక,
          .చివర = సూచిక + వ్యక్తిగత_కీలకం.meta
        }
      )),
    వ్యక్తిగత_కీలకం,
    uint8_t);
  సూచిక += వ్యక్తిగత_కీలకం.meta;
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d417(serialized,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ప్రారంభం = సూచిక, .చివర = సూచిక + ప్రజా_కీలకం.meta })),
    ప్రజా_కీలకం,
    uint8_t);
  సూచిక += ప్రజా_కీలకం.meta;
  Eurydice_mut_borrow_ముక్క_u8
  uu____0 =
    Eurydice_array_గమ్యం_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = సూచిక,
          .చివర = సూచిక + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_కొలత
        }
      ));
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_ec lvalue = libcrux_ml_kem_hash_functions_portable_H_4a_78(ప్రజా_కీలకం);
  Eurydice_ముక్క_copy(uu____0, Eurydice_array_గమ్యం_ముక్క_shared_01(&lvalue), uint8_t);
  సూచిక += LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_కొలత;
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = సూచిక,
          .చివర = సూచిక + implicit_rejection_విలువ.meta
        }
      )),
    implicit_rejection_విలువ,
    uint8_t);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.serialize_kem_secret_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SERIALIZED_KEY_LEN= 2400
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_7d
libcrux_ml_kem_ind_cca_serialize_kem_secret_కీలకం_52(
  Eurydice_borrow_ముక్క_u8 వ్యక్తిగత_కీలకం,
  Eurydice_borrow_ముక్క_u8 ప్రజా_కీలకం,
  Eurydice_borrow_ముక్క_u8 implicit_rejection_విలువ
)
{
  Eurydice_arr_7d బహిర్గతం = { .దత్తాంశం = { 0U } };
  libcrux_ml_kem_ind_cca_serialize_kem_secret_కీలకం_mut_52(వ్యక్తిగత_కీలకం,
    ప్రజా_కీలకం,
    implicit_rejection_విలువ,
    &బహిర్గతం);
  తిరిగి బహిర్గతం;
}

/**
 Packed API

 Generate a key pair.

 Depending on the `Vector` and `Hasher` used, this requires different hardware
 features
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.generate_keypair
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE libcrux_ml_kem_mlkem768_Ml_Kem768_కీలకం_Pair
libcrux_ml_kem_ind_cca_generate_keypair_b8(స్థిరరాశి Eurydice_arr_c7 *randomness)
{
  Eurydice_borrow_ముక్క_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_గమ్యం_subslice_shared_d47(randomness,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)0U,
          .చివర = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_కీలకం_GENERATION_విత్తనం_కొలత
        }
      ));
  Eurydice_borrow_ముక్క_u8
  implicit_rejection_విలువ =
    Eurydice_array_గమ్యం_subslice_from_shared_5f1(randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_కీలకం_GENERATION_విత్తనం_కొలత);
  libcrux_ml_kem_utils_extraction_helper_Keypair768
  uu____0 = libcrux_ml_kem_ind_cpa_generate_keypair_30(ind_cpa_keypair_randomness);
  Eurydice_arr_0e ind_cpa_వ్యక్తిగత_కీలకం = uu____0.fst;
  Eurydice_arr_5f ప్రజా_కీలకం = uu____0.snd;
  Eurydice_arr_7d
  secret_కీలకం_serialized =
    libcrux_ml_kem_ind_cca_serialize_kem_secret_కీలకం_52(Eurydice_array_గమ్యం_ముక్క_shared_f4(&ind_cpa_వ్యక్తిగత_కీలకం),
      Eurydice_array_గమ్యం_ముక్క_shared_ff(&ప్రజా_కీలకం),
      implicit_rejection_విలువ);
  Eurydice_arr_7d వ్యక్తిగత_కీలకం = libcrux_ml_kem_types_from_b2_79(secret_కీలకం_serialized);
  తిరిగి
    libcrux_ml_kem_types_from_17_bc(వ్యక్తిగత_కీలకం,
      libcrux_ml_kem_types_from_51_3d(ప్రజా_కీలకం));
}

/**
 Portable generate key pair.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.generate_keypair
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
స్థిర అంతఃవరుస libcrux_ml_kem_mlkem768_Ml_Kem768_కీలకం_Pair
libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_e9(
  స్థిరరాశి Eurydice_arr_c7 *randomness
)
{
  తిరిగి libcrux_ml_kem_ind_cca_generate_keypair_b8(randomness);
}

/**
 Generate ML-KEM 768 Key Pair
*/
స్థిర అంతఃవరుస libcrux_ml_kem_mlkem768_Ml_Kem768_కీలకం_Pair
libcrux_ml_kem_mlkem768_portable_generate_కీలకం_pair(Eurydice_arr_c7 randomness)
{
  తిరిగి libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_e9(&randomness);
}

/**
 Validate an ML-KEM private key.

 This implements the Hash check in 7.3 3.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.validate_private_key_only
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_వ్యక్తిగత_కీలకం_only_52(స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం)
{
  Eurydice_arr_ec
  t =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_గమ్యం_subslice_shared_d48(వ్యక్తిగత_కీలకం,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ప్రారంభం = (కొలత_t)384U * (కొలత_t)3U,
            .చివర = (కొలత_t)768U * (కొలత_t)3U + (కొలత_t)32U
          }
        )));
  Eurydice_borrow_ముక్క_u8
  expected =
    Eurydice_array_గమ్యం_subslice_shared_d48(వ్యక్తిగత_కీలకం,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)768U * (కొలత_t)3U + (కొలత_t)32U,
          .చివర = (కొలత_t)768U * (కొలత_t)3U + (కొలత_t)64U
        }
      ));
  తిరిగి Eurydice_array_eq_ముక్క_shared((కొలత_t)32U, &t, &expected, uint8_t, bool);
}

/**
 Validate an ML-KEM private key.

 This implements the Hash check in 7.3 3.
 Note that the size checks in 7.2 1 and 2 are covered by the `SECRET_KEY_SIZE`
 and `CIPHERTEXT_SIZE` in the `private_key` and `ciphertext` types.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.validate_private_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CIPHERTEXT_SIZE= 1088
*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_వ్యక్తిగత_కీలకం_ba(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం,
  స్థిరరాశి Eurydice_arr_2b *_ciphertext
)
{
  తిరిగి libcrux_ml_kem_ind_cca_validate_వ్యక్తిగత_కీలకం_only_52(వ్యక్తిగత_కీలకం);
}

/**
 Private key validation
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.validate_private_key
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CIPHERTEXT_SIZE= 1088
*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_వ్యక్తిగత_కీలకం_d3(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  తిరిగి libcrux_ml_kem_ind_cca_validate_వ్యక్తిగత_కీలకం_ba(వ్యక్తిగత_కీలకం, ciphertext);
}

/**
 Validate a private key.

 Returns `true` if valid, and `false` otherwise.
*/
స్థిర అంతఃవరుస bool
libcrux_ml_kem_mlkem768_portable_validate_వ్యక్తిగత_కీలకం(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  తిరిగి
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_వ్యక్తిగత_కీలకం_d3(వ్యక్తిగత_కీలకం,
      ciphertext);
}

/**
 Private key validation
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.validate_private_key_only
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_వ్యక్తిగత_కీలకం_only_3b(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం
)
{
  తిరిగి libcrux_ml_kem_ind_cca_validate_వ్యక్తిగత_కీలకం_only_52(వ్యక్తిగత_కీలకం);
}

/**
 Validate the private key only.

 Returns `true` if valid, and `false` otherwise.
*/
స్థిర అంతఃవరుస bool
libcrux_ml_kem_mlkem768_portable_validate_వ్యక్తిగత_కీలకం_only(స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం)
{
  తిరిగి
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_వ్యక్తిగత_కీలకం_only_3b(వ్యక్తిగత_కీలకం);
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::serialize::deserialize_ring_elements_reduced_out::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_ring_elements_reduced_out.call_mut_0b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_బహిర్గతం_call_mut_0b_68(
  శూన్య **_,
  కొలత_t tupled_వాదనలు
)
{
  తిరిగి libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
 This function deserializes ring elements and reduces the result by the field
 modulus.

 This function MUST NOT be used on secret inputs.
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_ring_elements_reduced_out
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_బహిర్గతం_68(
  Eurydice_borrow_ముక్క_u8 ప్రజా_కీలకం
)
{
  Eurydice_arr_bb0 arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_struct.దత్తాంశం[i] =
      libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_బహిర్గతం_call_mut_0b_68(&lvalue,
        i);
  }
  Eurydice_arr_bb0 deserialized_pk = arr_struct;
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(ప్రజా_కీలకం, &deserialized_pk);
  తిరిగి deserialized_pk;
}

/**
 Validate an ML-KEM public key.

 This implements the Modulus check in 7.2 2.
 Note that the size check in 7.2 1 is covered by the `PUBLIC_KEY_SIZE` in the
 `public_key` type.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.validate_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_ప్రజా_కీలకం_b6(స్థిరరాశి Eurydice_arr_5f *ప్రజా_కీలకం)
{
  Eurydice_arr_bb0
  deserialized_pk =
    libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_బహిర్గతం_68(Eurydice_array_గమ్యం_subslice_గమ్యం_shared_210(ప్రజా_కీలకం,
        libcrux_ml_kem_constants_ranked_బైట్లు_చొప్పున_ring_element((కొలత_t)3U)));
  Eurydice_arr_5f
  ప్రజా_కీలకం_serialized =
    libcrux_ml_kem_ind_cpa_serialize_ప్రజా_కీలకం_b6(&deserialized_pk,
      Eurydice_array_గమ్యం_subslice_from_shared_5f2(ప్రజా_కీలకం,
        libcrux_ml_kem_constants_ranked_బైట్లు_చొప్పున_ring_element((కొలత_t)3U)));
  తిరిగి Eurydice_array_eq((కొలత_t)1184U, ప్రజా_కీలకం, &ప్రజా_కీలకం_serialized, uint8_t);
}

/**
 Public key validation
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.validate_public_key
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_ప్రజా_కీలకం_3b(
  స్థిరరాశి Eurydice_arr_5f *ప్రజా_కీలకం
)
{
  తిరిగి libcrux_ml_kem_ind_cca_validate_ప్రజా_కీలకం_b6(ప్రజా_కీలకం);
}

/**
 Validate a public key.

 Returns `true` if valid, and `false` otherwise.
*/
స్థిర అంతఃవరుస bool
libcrux_ml_kem_mlkem768_portable_validate_ప్రజా_కీలకం(స్థిరరాశి Eurydice_arr_5f *ప్రజా_కీలకం)
{
  తిరిగి libcrux_ml_kem_ind_cca_instantiations_portable_validate_ప్రజా_కీలకం_3b(ప్రజా_కీలకం);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51_s
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51 ind_cpa_ప్రజా_కీలకం;
  Eurydice_arr_ec ప్రజా_కీలకం_hash;
}
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51;

రకనిర్వచనం libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51
libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ప్రజా_కీలకం_Unpacked;

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPrivateKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
రకనిర్వచనం నిర్మాణం libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_వ్యక్తిగత_కీలకం_Unpacked_51_s
{
  Eurydice_arr_bb0 ind_cpa_వ్యక్తిగత_కీలకం;
  Eurydice_arr_ec implicit_rejection_విలువ;
}
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_వ్యక్తిగత_కీలకం_Unpacked_51;

రకనిర్వచనం నిర్మాణం libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked_s
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_వ్యక్తిగత_కీలకం_Unpacked_51 వ్యక్తిగత_కీలకం;
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 ప్రజా_కీలకం;
}
libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked;

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.decapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_unpacked_decapsulate_0c(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_ec
  decrypted =
    libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(&కీలకం_pair->వ్యక్తిగత_కీలకం.ind_cpa_వ్యక్తిగత_కీలకం,
      ciphertext);
  Eurydice_arr_c7
  గమ్యం_hash0 =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_గమ్యం_ముక్క_shared_01(&decrypted));
  Eurydice_mut_borrow_ముక్క_u8
  uu____0 =
    Eurydice_array_గమ్యం_subslice_from_mut_5f1(&గమ్యం_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత);
  Eurydice_ముక్క_copy(uu____0,
    Eurydice_array_గమ్యం_ముక్క_shared_01(&కీలకం_pair->ప్రజా_కీలకం.ప్రజా_కీలకం_hash),
    uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_గమ్యం_ముక్క_shared_17(&గమ్యం_hash0));
  Eurydice_borrow_ముక్క_u8_x2
  uu____1 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_ముక్క_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_af
  గమ్యం_hash =
    libcrux_ml_kem_utils_into_padded_array_66(Eurydice_array_గమ్యం_ముక్క_shared_01(&కీలకం_pair->వ్యక్తిగత_కీలకం.implicit_rejection_విలువ));
  Eurydice_mut_borrow_ముక్క_u8
  uu____2 =
    Eurydice_array_గమ్యం_subslice_from_mut_5f2(&గమ్యం_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత);
  Eurydice_ముక్క_copy(uu____2, libcrux_ml_kem_types_as_ref_c1_52(ciphertext), uint8_t);
  Eurydice_arr_ec
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_array_గమ్యం_ముక్క_shared_81(&గమ్యం_hash));
  Eurydice_arr_2b
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&కీలకం_pair->ప్రజా_కీలకం.ind_cpa_ప్రజా_కీలకం,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_ముక్క_u8 uu____3 = libcrux_ml_kem_types_as_ref_c1_52(ciphertext);
  uint8_t
  selector =
    libcrux_ml_kem_constant_సమయం_ops_compare_ciphertexts_లోపల_constant_సమయం(uu____3,
      Eurydice_array_గమ్యం_ముక్క_shared_06(&expected_ciphertext));
  తిరిగి
    libcrux_ml_kem_constant_సమయం_ops_select_shared_secret_లోపల_constant_సమయం(shared_secret,
      Eurydice_array_గమ్యం_ముక్క_shared_01(&implicit_rejection_shared_secret),
      selector);
}

/**
 Unpacked decapsulate
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.decapsulate
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_19(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  తిరిగి libcrux_ml_kem_ind_cca_unpacked_decapsulate_0c(కీలకం_pair, ciphertext);
}

/**
 Decapsulate ML-KEM 768 (unpacked)

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an unpacked key pair of type [`MlKem768KeyPairUnpacked`]
 and an [`MlKem768Ciphertext`].
*/
స్థిర అంతఃవరుస Eurydice_arr_ec
libcrux_ml_kem_mlkem768_portable_unpacked_decapsulate(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *వ్యక్తిగత_కీలకం,
  స్థిరరాశి Eurydice_arr_2b *ciphertext
)
{
  తిరిగి
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_19(వ్యక్తిగత_కీలకం,
      ciphertext);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.encaps_prepare
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_c7
libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_13(
  Eurydice_borrow_ముక్క_u8 randomness,
  Eurydice_borrow_ముక్క_u8 pk_hash
)
{
  Eurydice_arr_c7 గమ్యం_hash = libcrux_ml_kem_utils_into_padded_array_c9(randomness);
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_subslice_from_mut_5f1(&గమ్యం_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_కొలత),
    pk_hash,
    uint8_t);
  తిరిగి
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_గమ్యం_ముక్క_shared_17(&గమ్యం_hash));
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.encapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- VECTOR_U_BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_unpacked_encapsulate_a7(
  స్థిరరాశి libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *ప్రజా_కీలకం,
  స్థిరరాశి Eurydice_arr_ec *randomness
)
{
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_13(Eurydice_array_గమ్యం_ముక్క_shared_01(randomness),
      Eurydice_array_గమ్యం_ముక్క_shared_01(&ప్రజా_కీలకం->ప్రజా_కీలకం_hash));
  Eurydice_borrow_ముక్క_u8_x2
  uu____0 =
    Eurydice_ముక్క_విభజించు_at(Eurydice_array_గమ్యం_ముక్క_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_కొలత,
      uint8_t,
      Eurydice_borrow_ముక్క_u8_x2);
  Eurydice_borrow_ముక్క_u8 shared_secret = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 pseudorandomness = uu____0.snd;
  Eurydice_arr_2b
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&ప్రజా_కీలకం->ind_cpa_ప్రజా_కీలకం,
      randomness,
      pseudorandomness);
  Eurydice_arr_ec shared_secret_array = { .దత్తాంశం = { 0U } };
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_01(&shared_secret_array),
    shared_secret,
    uint8_t);
  తిరిగి
    (
      KRML_CLITERAL(tuple_f4){
        .fst = libcrux_ml_kem_types_from_19_52(ciphertext),
        .snd = shared_secret_array
      }
    );
}

/**
 Unpacked encapsulate
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.encapsulate
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- VECTOR_U_BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_26(
  స్థిరరాశి libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *ప్రజా_కీలకం,
  స్థిరరాశి Eurydice_arr_ec *randomness
)
{
  తిరిగి libcrux_ml_kem_ind_cca_unpacked_encapsulate_a7(ప్రజా_కీలకం, randomness);
}

/**
 Encapsulate ML-KEM 768 (unpacked)

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an unpacked public key of type [`MlKem768PublicKeyUnpacked`],
 the SHA3-256 hash of this public key, and [`SHARED_SECRET_SIZE`] bytes of `randomness`.
*/
స్థిర అంతఃవరుస tuple_f4
libcrux_ml_kem_mlkem768_portable_unpacked_encapsulate(
  స్థిరరాశి libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *ప్రజా_కీలకం,
  Eurydice_arr_ec randomness
)
{
  తిరిగి
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_26(ప్రజా_కీలకం,
      &randomness);
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::ind_cca::unpacked::transpose_a::closure::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.transpose_a.closure.call_mut_b4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_ind_cca_unpacked_transpose_a_సంవృతం_call_mut_b4_68(
  శూన్య **_,
  కొలత_t tupled_వాదనలు
)
{
  తిరిగి libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
This function found in impl {core::ops::function::FnMut<(usize), [libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]; K]> for libcrux_ml_kem::ind_cca::unpacked::transpose_a::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.transpose_a.call_mut_22
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_bb0
libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_22_68(శూన్య **_, కొలత_t tupled_వాదనలు)
{
  Eurydice_arr_bb0 arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_struct.దత్తాంశం[i] =
      libcrux_ml_kem_ind_cca_unpacked_transpose_a_సంవృతం_call_mut_b4_68(&lvalue,
        i);
  }
  తిరిగి arr_struct;
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.clone_c1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
స్థిర అంతఃవరుస Eurydice_arr_9e
libcrux_ml_kem_polynomial_clone_c1_ea(స్థిరరాశి Eurydice_arr_9e *self)
{
  తిరిగి
    core_array__core__clone__Clone_for__T__N___clone((కొలత_t)16U,
      self,
      Eurydice_arr_d6,
      Eurydice_arr_9e);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.transpose_a
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర అంతఃవరుస Eurydice_arr_c10
libcrux_ml_kem_ind_cca_unpacked_transpose_a_68(Eurydice_arr_c10 ind_cpa_a)
{
  Eurydice_arr_c10 arr_struct;
  కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    శూన్య *lvalue = (శూన్య *)0U;
    arr_struct.దత్తాంశం[i] = libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_22_68(&lvalue, i);
  }
  Eurydice_arr_c10 A = arr_struct;
  కొరకు (కొలత_t i0 = (కొలత_t)0U; i0 < (కొలత_t)3U; i0++)
  {
    కొలత_t i1 = i0;
    కొరకు (కొలత_t i = (కొలత_t)0U; i < (కొలత_t)3U; i++)
    {
      కొలత_t j = i;
      Eurydice_arr_9e uu____0 = libcrux_ml_kem_polynomial_clone_c1_ea(&ind_cpa_a.దత్తాంశం[j].దత్తాంశం[i1]);
      A.దత్తాంశం[i1].దత్తాంశం[j] = uu____0;
    }
  }
  తిరిగి A;
}

/**
 Generate Unpacked Keys
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.generate_keypair
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_unpacked_generate_keypair_b8(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *బహిర్గతం
)
{
  Eurydice_borrow_ముక్క_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_గమ్యం_subslice_shared_d47(&randomness,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ప్రారంభం = (కొలత_t)0U,
          .చివర = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_కీలకం_GENERATION_విత్తనం_కొలత
        }
      ));
  Eurydice_borrow_ముక్క_u8
  implicit_rejection_విలువ =
    Eurydice_array_గమ్యం_subslice_from_shared_5f1(&randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_కీలకం_GENERATION_విత్తనం_కొలత);
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(ind_cpa_keypair_randomness,
    &బహిర్గతం->వ్యక్తిగత_కీలకం.ind_cpa_వ్యక్తిగత_కీలకం,
    &బహిర్గతం->ప్రజా_కీలకం.ind_cpa_ప్రజా_కీలకం);
  Eurydice_arr_c10
  A = libcrux_ml_kem_ind_cca_unpacked_transpose_a_68(బహిర్గతం->ప్రజా_కీలకం.ind_cpa_ప్రజా_కీలకం.A);
  బహిర్గతం->ప్రజా_కీలకం.ind_cpa_ప్రజా_కీలకం.A = A;
  Eurydice_arr_5f
  pk_serialized =
    libcrux_ml_kem_ind_cpa_serialize_ప్రజా_కీలకం_b6(&బహిర్గతం->ప్రజా_కీలకం.ind_cpa_ప్రజా_కీలకం.t_as_ntt,
      Eurydice_array_గమ్యం_ముక్క_shared_01(&బహిర్గతం->ప్రజా_కీలకం.ind_cpa_ప్రజా_కీలకం.విత్తనం_for_A));
  Eurydice_arr_ec
  uu____0 =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_గమ్యం_ముక్క_shared_ff(&pk_serialized));
  బహిర్గతం->ప్రజా_కీలకం.ప్రజా_కీలకం_hash = uu____0;
  Eurydice_arr_ec arr;
  జ్ఞాపకం_నకలు(arr.దత్తాంశం, implicit_rejection_విలువ.ptr, (కొలత_t)32U * పరిమాణం (uint8_t));
  Eurydice_arr_ec
  uu____1 =
    core_ఫలితం_unwrap_26_39((
        KRML_CLITERAL(core_ఫలితం_ఫలితం_07){ .ట్యాగ్ = core_ఫలితం_Ok, .val = { .case_Ok = arr } }
      ));
  బహిర్గతం->వ్యక్తిగత_కీలకం.implicit_rejection_విలువ = uu____1;
}

/**
 Generate a key pair
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.generate_keypair
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_e9(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *బహిర్గతం
)
{
  libcrux_ml_kem_ind_cca_unpacked_generate_keypair_b8(randomness, బహిర్గతం);
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_kem_mlkem768_portable_unpacked_generate_కీలకం_pair_mut(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_e9(randomness,
    కీలకం_pair);
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.default_30
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51
libcrux_ml_kem_ind_cca_unpacked_default_30_68(శూన్య)
{
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51){
        .ind_cpa_ప్రజా_కీలకం = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68(),
        .ప్రజా_కీలకం_hash = { .దత్తాంశం = { 0U } }
      }
    );
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.default_7b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked
libcrux_ml_kem_ind_cca_unpacked_default_7b_68(శూన్య)
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_వ్యక్తిగత_కీలకం_Unpacked_51
  uu____0 =
    {
      .ind_cpa_వ్యక్తిగత_కీలకం = libcrux_ml_kem_ind_cpa_unpacked_default_70_68(),
      .implicit_rejection_విలువ = { .దత్తాంశం = { 0U } }
    };
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked){
        .వ్యక్తిగత_కీలకం = uu____0,
        .ప్రజా_కీలకం = libcrux_ml_kem_ind_cca_unpacked_default_30_68()
      }
    );
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
స్థిర అంతఃవరుస libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked
libcrux_ml_kem_mlkem768_portable_unpacked_generate_కీలకం_pair(Eurydice_arr_c7 randomness)
{
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked
  కీలకం_pair = libcrux_ml_kem_ind_cca_unpacked_default_7b_68();
  libcrux_ml_kem_mlkem768_portable_unpacked_generate_కీలకం_pair_mut(randomness, &కీలకం_pair);
  తిరిగి కీలకం_pair;
}

/**
 Create a new, empty unpacked key.
*/
స్థిర అంతఃవరుస libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked
libcrux_ml_kem_mlkem768_portable_unpacked_init_కీలకం_pair(శూన్య)
{
  తిరిగి libcrux_ml_kem_ind_cca_unpacked_default_7b_68();
}

/**
 Create a new, empty unpacked public key.
*/
స్థిర అంతఃవరుస libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51
libcrux_ml_kem_mlkem768_portable_unpacked_init_ప్రజా_కీలకం(శూన్య)
{
  తిరిగి libcrux_ml_kem_ind_cca_unpacked_default_30_68();
}

/**
 Take a serialized private key and generate an unpacked key pair from it.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.keys_from_private_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_unpacked_కీలకాలు_from_వ్యక్తిగత_కీలకం_01(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair
)
{
  Eurydice_borrow_ముక్క_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_వ్యక్తిగత_కీలకం_64(Eurydice_array_గమ్యం_ముక్క_shared_51(వ్యక్తిగత_కీలకం));
  Eurydice_borrow_ముక్క_u8 ind_cpa_secret_కీలకం = uu____0.fst;
  Eurydice_borrow_ముక్క_u8 ind_cpa_ప్రజా_కీలకం = uu____0.snd;
  Eurydice_borrow_ముక్క_u8 ind_cpa_ప్రజా_కీలకం_hash = uu____0.thd;
  Eurydice_borrow_ముక్క_u8 implicit_rejection_విలువ = uu____0.f3;
  libcrux_ml_kem_ind_cpa_deserialize_సదిశ_68(ind_cpa_secret_కీలకం,
    &కీలకం_pair->వ్యక్తిగత_కీలకం.ind_cpa_వ్యక్తిగత_కీలకం);
  libcrux_ml_kem_ind_cpa_build_unpacked_ప్రజా_కీలకం_mut_05(ind_cpa_ప్రజా_కీలకం,
    &కీలకం_pair->ప్రజా_కీలకం.ind_cpa_ప్రజా_కీలకం);
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_01(&కీలకం_pair->ప్రజా_కీలకం.ప్రజా_కీలకం_hash),
    ind_cpa_ప్రజా_కీలకం_hash,
    uint8_t);
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_01(&కీలకం_pair->వ్యక్తిగత_కీలకం.implicit_rejection_విలువ),
    implicit_rejection_విలువ,
    uint8_t);
  Eurydice_ముక్క_copy(Eurydice_array_గమ్యం_ముక్క_mut_01(&కీలకం_pair->ప్రజా_కీలకం.ind_cpa_ప్రజా_కీలకం.విత్తనం_for_A),
    Eurydice_ముక్క_subslice_from_shared_6d(ind_cpa_ప్రజా_కీలకం, (కొలత_t)1152U),
    uint8_t);
}

/**
 Take a serialized private key and generate an unpacked key pair from it.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.keypair_from_private_key
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_వ్యక్తిగత_కీలకం_71(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair
)
{
  libcrux_ml_kem_ind_cca_unpacked_కీలకాలు_from_వ్యక్తిగత_కీలకం_01(వ్యక్తిగత_కీలకం, కీలకం_pair);
}

/**
 Get an unpacked key from a private key.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_kem_mlkem768_portable_unpacked_కీలకం_pair_from_వ్యక్తిగత_mut(
  స్థిరరాశి Eurydice_arr_7d *వ్యక్తిగత_కీలకం,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_వ్యక్తిగత_కీలకం_71(వ్యక్తిగత_కీలకం,
    కీలకం_pair);
}

/**
 Get the serialized private key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_private_key_mut_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_unpacked_serialized_వ్యక్తిగత_కీలకం_mut_11_21(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *self,
  Eurydice_arr_7d *serialized
)
{
  libcrux_ml_kem_utils_extraction_helper_Keypair768
  uu____0 =
    libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_కీలకం_30(&self->ప్రజా_కీలకం.ind_cpa_ప్రజా_కీలకం,
      &self->వ్యక్తిగత_కీలకం.ind_cpa_వ్యక్తిగత_కీలకం);
  Eurydice_arr_0e ind_cpa_వ్యక్తిగత_కీలకం = uu____0.fst;
  Eurydice_arr_5f ind_cpa_ప్రజా_కీలకం = uu____0.snd;
  libcrux_ml_kem_ind_cca_serialize_kem_secret_కీలకం_mut_52(Eurydice_array_గమ్యం_ముక్క_shared_f4(&ind_cpa_వ్యక్తిగత_కీలకం),
    Eurydice_array_గమ్యం_ముక్క_shared_ff(&ind_cpa_ప్రజా_కీలకం),
    Eurydice_array_గమ్యం_ముక్క_shared_01(&self->వ్యక్తిగత_కీలకం.implicit_rejection_విలువ),
    serialized);
}

/**
 Get the serialized private key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_private_key_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_7d
libcrux_ml_kem_ind_cca_unpacked_serialized_వ్యక్తిగత_కీలకం_11_21(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *self
)
{
  Eurydice_arr_7d sk = libcrux_ml_kem_types_default_d3_79();
  libcrux_ml_kem_ind_cca_unpacked_serialized_వ్యక్తిగత_కీలకం_mut_11_21(self, &sk);
  తిరిగి sk;
}

/**
 Get the serialized private key.
*/
స్థిర అంతఃవరుస Eurydice_arr_7d
libcrux_ml_kem_mlkem768_portable_unpacked_కీలకం_pair_serialized_వ్యక్తిగత_కీలకం(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair
)
{
  తిరిగి libcrux_ml_kem_ind_cca_unpacked_serialized_వ్యక్తిగత_కీలకం_11_21(కీలకం_pair);
}

/**
 Get the serialized private key.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_kem_mlkem768_portable_unpacked_కీలకం_pair_serialized_వ్యక్తిగత_కీలకం_mut(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair,
  Eurydice_arr_7d *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_వ్యక్తిగత_కీలకం_mut_11_21(కీలకం_pair, serialized);
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_dd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cca_unpacked_serialized_dd_b6(
  స్థిరరాశి libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *self
)
{
  తిరిగి
    libcrux_ml_kem_types_from_51_3d(libcrux_ml_kem_ind_cpa_serialize_ప్రజా_కీలకం_b6(&self->ind_cpa_ప్రజా_కీలకం.t_as_ntt,
        Eurydice_array_గమ్యం_ముక్క_shared_01(&self->ind_cpa_ప్రజా_కీలకం.విత్తనం_for_A)));
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_public_key_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cca_unpacked_serialized_ప్రజా_కీలకం_11_b6(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *self
)
{
  తిరిగి libcrux_ml_kem_ind_cca_unpacked_serialized_dd_b6(&self->ప్రజా_కీలకం);
}

/**
 Get the serialized public key.
*/
స్థిర అంతఃవరుస Eurydice_arr_5f
libcrux_ml_kem_mlkem768_portable_unpacked_కీలకం_pair_serialized_ప్రజా_కీలకం(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair
)
{
  తిరిగి libcrux_ml_kem_ind_cca_unpacked_serialized_ప్రజా_కీలకం_11_b6(కీలకం_pair);
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_mut_dd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(
  స్థిరరాశి libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *self,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_ప్రజా_కీలకం_mut_b6(&self->ind_cpa_ప్రజా_కీలకం.t_as_ntt,
    Eurydice_array_గమ్యం_ముక్క_shared_01(&self->ind_cpa_ప్రజా_కీలకం.విత్తనం_for_A),
    serialized);
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_public_key_mut_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_unpacked_serialized_ప్రజా_కీలకం_mut_11_b6(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *self,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(&self->ప్రజా_కీలకం, serialized);
}

/**
 Get the serialized public key.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_kem_mlkem768_portable_unpacked_కీలకం_pair_serialized_ప్రజా_కీలకం_mut(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_ప్రజా_కీలకం_mut_11_b6(కీలకం_pair, serialized);
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.clone_91
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర అంతఃవరుస libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51
libcrux_ml_kem_ind_cpa_unpacked_clone_91_68(
  స్థిరరాశి libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51 *self
)
{
  Eurydice_arr_bb0
  uu____0 =
    core_array__core__clone__Clone_for__T__N___clone((కొలత_t)3U,
      &self->t_as_ntt,
      Eurydice_arr_9e,
      Eurydice_arr_bb0);
  Eurydice_arr_ec
  uu____1 =
    core_array__core__clone__Clone_for__T__N___clone((కొలత_t)32U,
      &self->విత్తనం_for_A,
      uint8_t,
      Eurydice_arr_ec);
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51){
        .t_as_ntt = uu____0,
        .విత్తనం_for_A = uu____1,
        .A = core_array__core__clone__Clone_for__T__N___clone((కొలత_t)3U,
          &self->A,
          Eurydice_arr_bb0,
          Eurydice_arr_c10)
      }
    );
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.clone_d7
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర అంతఃవరుస libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51
libcrux_ml_kem_ind_cca_unpacked_clone_d7_68(
  స్థిరరాశి libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *self
)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ప్రజా_కీలకం_Unpacked_51
  uu____0 = libcrux_ml_kem_ind_cpa_unpacked_clone_91_68(&self->ind_cpa_ప్రజా_కీలకం);
  తిరిగి
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51){
        .ind_cpa_ప్రజా_కీలకం = uu____0,
        .ప్రజా_కీలకం_hash = core_array__core__clone__Clone_for__T__N___clone((కొలత_t)32U,
          &self->ప్రజా_కీలకం_hash,
          uint8_t,
          Eurydice_arr_ec)
      }
    );
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.public_key_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
స్థిర KRML_MUSTINLINE స్థిరరాశి
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51
*libcrux_ml_kem_ind_cca_unpacked_ప్రజా_కీలకం_11_68(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *self
)
{
  తిరిగి &self->ప్రజా_కీలకం;
}

/**
 Get the unpacked public key.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_kem_mlkem768_portable_unpacked_ప్రజా_కీలకం(
  స్థిరరాశి libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_కీలకం_Pair_Unpacked *కీలకం_pair,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *pk
)
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51
  uu____0 =
    libcrux_ml_kem_ind_cca_unpacked_clone_d7_68(libcrux_ml_kem_ind_cca_unpacked_ప్రజా_కీలకం_11_68(కీలకం_pair));
  pk[0U] = uu____0;
}

/**
 Get the serialized public key.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_kem_mlkem768_portable_unpacked_serialized_ప్రజా_కీలకం(
  స్థిరరాశి libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *ప్రజా_కీలకం,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(ప్రజా_కీలకం, serialized);
}

/**
 Generate an unpacked key from a serialized key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.unpack_public_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_unpacked_unpack_ప్రజా_కీలకం_22(
  స్థిరరాశి Eurydice_arr_5f *ప్రజా_కీలకం,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *unpacked_ప్రజా_కీలకం
)
{
  Eurydice_borrow_ముక్క_u8
  uu____0 = Eurydice_array_గమ్యం_subslice_గమ్యం_shared_210(ప్రజా_కీలకం, (కొలత_t)1152U);
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(uu____0,
    &unpacked_ప్రజా_కీలకం->ind_cpa_ప్రజా_కీలకం.t_as_ntt);
  unpacked_ప్రజా_కీలకం->ind_cpa_ప్రజా_కీలకం.విత్తనం_for_A =
    libcrux_ml_kem_utils_into_padded_array_ce(Eurydice_array_గమ్యం_subslice_from_shared_5f2(ప్రజా_కీలకం,
        (కొలత_t)1152U));
  Eurydice_arr_c10 *uu____2 = &unpacked_ప్రజా_కీలకం->ind_cpa_ప్రజా_కీలకం.A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31
  lvalue =
    libcrux_ml_kem_utils_into_padded_array_de(Eurydice_array_గమ్యం_subslice_from_shared_5f2(ప్రజా_కీలకం,
        (కొలత_t)1152U));
  libcrux_ml_kem_మాతృక_sample_మాతృక_A_91(uu____2, &lvalue, false);
  Eurydice_arr_ec
  uu____3 =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_గమ్యం_ముక్క_shared_ff(libcrux_ml_kem_types_as_ముక్క_e6_3d(ప్రజా_కీలకం)));
  unpacked_ప్రజా_కీలకం->ప్రజా_కీలకం_hash = uu____3;
}

/**
 Get the unpacked public key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.unpack_public_key
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
స్థిర KRML_MUSTINLINE శూన్య
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_ప్రజా_కీలకం_d3(
  స్థిరరాశి Eurydice_arr_5f *ప్రజా_కీలకం,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *unpacked_ప్రజా_కీలకం
)
{
  libcrux_ml_kem_ind_cca_unpacked_unpack_ప్రజా_కీలకం_22(ప్రజా_కీలకం, unpacked_ప్రజా_కీలకం);
}

/**
 Get the unpacked public key.
*/
స్థిర అంతఃవరుస శూన్య
libcrux_ml_kem_mlkem768_portable_unpacked_unpacked_ప్రజా_కీలకం(
  స్థిరరాశి Eurydice_arr_5f *ప్రజా_కీలకం,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ప్రజా_కీలకం_Unpacked_51 *unpacked_ప్రజా_కీలకం
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_ప్రజా_కీలకం_d3(ప్రజా_కీలకం,
    unpacked_ప్రజా_కీలకం);
}

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#నిర్వచించు libcrux_mlkem768_portable_H_DEFINED
#అయితే_ముగింపు /* libcrux_mlkem768_portable_H */


/* rename some types to be a bit more ergonomic */

/* ML-KEM 768 */
రకనిర్వచనం Eurydice_arr_c7 libcrux_mlkem768_keypair_rnd;
రకనిర్వచనం Eurydice_arr_ec libcrux_mlkem768_enc_rnd;
రకనిర్వచనం libcrux_ml_kem_mlkem768_Ml_Kem768_కీలకం_Pair libcrux_mlkem768_keypair;
రకనిర్వచనం Eurydice_arr_5f libcrux_mlkem768_pk;
రకనిర్వచనం Eurydice_arr_7d libcrux_mlkem768_sk;
రకనిర్వచనం Eurydice_arr_2b libcrux_mlkem768_ciphertext;
రకనిర్వచనం tuple_f4 libcrux_mlkem768_enc_ఫలితం;
రకనిర్వచనం Eurydice_arr_ec libcrux_mlkem768_dec_ఫలితం;
/* ML-DSA 44 */
రకనిర్వచనం Eurydice_arr_ec libcrux_mldsa44_keypair_rnd;
రకనిర్వచనం libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_కీలకం_Pair
    libcrux_mldsa44_keypair;
రకనిర్వచనం Eurydice_arr_10 libcrux_mldsa44_sk;
రకనిర్వచనం Eurydice_arr_02 libcrux_mldsa44_pk;
రకనిర్వచనం Eurydice_borrow_ముక్క_u8 libcrux_mldsa44_సందేశం;
రకనిర్వచనం Eurydice_arr_ec libcrux_mldsa44_sign_rnd;
రకనిర్వచనం core_ఫలితం_ఫలితం_48 libcrux_mldsa44_sign_ఫలితం;
రకనిర్వచనం core_ఫలితం_ఫలితం_41 libcrux_mldsa44_verify_ఫలితం;
రకనిర్వచనం Eurydice_arr_85 libcrux_mldsa44_signature;
/* ML-DSA 65 */
రకనిర్వచనం Eurydice_arr_ec libcrux_mldsa65_keypair_rnd;
రకనిర్వచనం libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_కీలకం_Pair
    libcrux_mldsa65_keypair;
రకనిర్వచనం Eurydice_arr_24 libcrux_mldsa65_sk;
రకనిర్వచనం Eurydice_arr_29 libcrux_mldsa65_pk;
రకనిర్వచనం Eurydice_borrow_ముక్క_u8 libcrux_mldsa65_సందేశం;
రకనిర్వచనం Eurydice_arr_ec libcrux_mldsa65_sign_rnd;
రకనిర్వచనం core_ఫలితం_ఫలితం_8c libcrux_mldsa65_sign_ఫలితం;
రకనిర్వచనం core_ఫలితం_ఫలితం_41 libcrux_mldsa65_verify_ఫలితం;
రకనిర్వచనం Eurydice_arr_0c libcrux_mldsa65_signature;
/* ML-DSA 87 */
రకనిర్వచనం Eurydice_arr_ec libcrux_mldsa87_keypair_rnd;
రకనిర్వచనం libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_కీలకం_Pair
    libcrux_mldsa87_keypair;
రకనిర్వచనం Eurydice_arr_e2 libcrux_mldsa87_sk;
రకనిర్వచనం Eurydice_arr_43 libcrux_mldsa87_pk;
రకనిర్వచనం Eurydice_borrow_ముక్క_u8 libcrux_mldsa87_సందేశం;
రకనిర్వచనం Eurydice_arr_ec libcrux_mldsa87_sign_rnd;
రకనిర్వచనం core_ఫలితం_ఫలితం_8b libcrux_mldsa87_sign_ఫలితం;
రకనిర్వచనం core_ఫలితం_ఫలితం_41 libcrux_mldsa87_verify_ఫలితం;
రకనిర్వచనం Eurydice_arr_93 libcrux_mldsa87_signature;

#నిర్వచించు LIBCRUX_ఫలితం_OK	core_ఫలితం_Ok

