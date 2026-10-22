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

#अगर !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#पूर्ण_अगर
#घोषणा KRML_MUSTINLINE अंतरभूत
#घोषणा KRML_NOINLINE __attribute__((noinline, unused))
#घोषणा KRML_HOST_EPRINTF(...)
#घोषणा KRML_HOST_EXIT(x) fatal_f("internal error")
#घोषणा KRML_UNION_CONSTRUCTOR(T)

अटल अंतरभूत व्योम
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

अटल अंतरभूत व्योम
store32_le(uint8_t dst[4], uint32_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
	dst[2] = (src >> 16) & 0xff;
	dst[3] = (src >> 24) & 0xff;
}

अटल अंतरभूत व्योम
store16_le(uint8_t dst[2], uint16_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
}

अटल अंतरभूत व्योम
store32_be(uint8_t dst[4], uint32_t src)
{
	dst[0] = (src >> 24) & 0xff;
	dst[1] = (src >> 16) & 0xff;
	dst[2] = (src >> 8) & 0xff;
	dst[3] = src & 0xff;
}

अटल अंतरभूत uint64_t
load64_le(uint8_t src[8])
{
	वापस (uint64_t)(src[0]) |
	    ((uint64_t)(src[1]) << 8) |
	    ((uint64_t)(src[2]) << 16) |
	    ((uint64_t)(src[3]) << 24) |
	    ((uint64_t)(src[4]) << 32) |
	    ((uint64_t)(src[5]) << 40) |
	    ((uint64_t)(src[6]) << 48) |
	    ((uint64_t)(src[7]) << 56);
}

अटल अंतरभूत uint32_t
load32_le(uint8_t src[4])
{
	वापस (uint32_t)(src[0]) |
	    ((uint32_t)(src[1]) << 8) |
	    ((uint32_t)(src[2]) << 16) |
	    ((uint32_t)(src[3]) << 24);
}

अटल अंतरभूत uint16_t
load16_le(uint8_t src[4])
{
	वापस (uint16_t)(src[0]) |
	    ((uint16_t)(src[1]) << 8);
}

#अगर_घोषित MISSING_BUILTIN_POPCOUNT
अटल अंतरभूत अचिन्हित पूर्णांक
__builtin_popcount(अचिन्हित पूर्णांक अंक)
{
  स्थिर पूर्णांक v[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
  वापस v[अंक & 0xf] + v[(अंक >> 4) & 0xf];
}
#पूर्ण_अगर

/* from libcrux/combined_extraction/generated/eurydice_glue.h */
#आशय once


#अगर_घोषित _MSC_VER
// For __popcnt
#पूर्ण_अगर


// C++ HELPERS

#अगर defined(__cplusplus)

#अगर_अघोषित KRML_HOST_EPRINTF
#घोषणा KRML_HOST_EPRINTF(...) ख_लिखो(मानक_त्रुटि, __VA_ARGS__)
#पूर्ण_अगर


#अगर_अघोषित __cpp_lib_type_identity
ढाँचा <class T>
काष्ठा type_identity {
  using type = T;
};

ढाँचा <class T>
using type_identity_t = typename type_identity<T>::type;
#अन्यथा
using std::type_identity_t;
#पूर्ण_अगर

#घोषणा KRML_UNION_CONSTRUCTOR(T)                              \
  ढाँचा <typename V>                                        \
  constexpr T(पूर्णांक t, V U::*m, type_identity_t<V> v) : tag(t) { \
    val.*m = std::move(v);                                     \
  }                                                            \
  T() = शेष;

#पूर्ण_अगर

// GENERAL-PURPOSE STUFF

#घोषणा निचला_Star_Ignore_ignore(e, t, _ret_t) ((व्योम)e)

#घोषणा EURYDICE_ASSERT(test, संदेश)                                            \
  करो {                                                                        \
    अगर (!(test)) {                                                            \
      ख_लिखो(मानक_त्रुटि, "assertion \"%s\" failed: file \"%s\", line %d\n", संदेश, \
              __खाता__, __LINE__);                                            \
      निकास(255);                                                              \
    }                                                                         \
  } जबतक (0)

// SIZEOF, ALIGNOF

#घोषणा Eurydice_sizeof(t) माप(t)

#घोषणा Eurydice_alignof(t) alignof(t)

// SLICES, ARRAYS, ETC.

// For convenience, we give these common slice types, below, a distinguished
// status and rather than emit them in the client code, we skip their
// code-generation in Cleanup3.ml and write them by hand here. This makes it
// easy to write interop code that brings those definitions in scope.

// &[u8]
प्रकार काष्ठा Eurydice_borrow_slice_u8_s {
  स्थिर uint8_t *ptr;
  माप_प्रकार meta;
} Eurydice_borrow_slice_u8;

// &[u16]
प्रकार काष्ठा Eurydice_borrow_slice_i16_s {
  स्थिर int16_t *ptr;
  माप_प्रकार meta;
} Eurydice_borrow_slice_i16;

// &mut [u8]
प्रकार काष्ठा Eurydice_mut_borrow_slice_u8_s {
  uint8_t *ptr;
  माप_प्रकार meta;
} Eurydice_mut_borrow_slice_u8;

// &mut [u16]
प्रकार काष्ठा Eurydice_mut_borrow_slice_i16_s {
  int16_t *ptr;
  माप_प्रकार meta;
} Eurydice_mut_borrow_slice_i16;

#अगर defined(__cplusplus)
#घोषणा KRML_CLITERAL(type) type
#अन्यथा
#घोषणा KRML_CLITERAL(type) (type)
#पूर्ण_अगर

#अगर defined(__cplusplus) && defined(__cpp_designated_initializers) || \
    !(defined(__cplusplus))
#घोषणा EURYDICE_CFIELD(X) X
#अन्यथा
#घोषणा EURYDICE_CFIELD(X)
#पूर्ण_अगर

#घोषणा Eurydice_array_repeat(dst, len, init, t) \
  ERROR "should've been desugared"

// Copy a slice with memcopy
#घोषणा Eurydice_slice_copy(dst, src, t) \
  स_नकल(dst.ptr, src.ptr, dst.meta * माप(t))

#घोषणा core_array___T__N___as_slice(len_, ptr_, t, ret_t)   \
  (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ptr =)(ptr_)->तथ्य, \
                        EURYDICE_CFIELD(.meta =) len_})

#घोषणा core_array__core__clone__Clone_for__T__N___clone(len, src, elem_type, \
                                                         _ret_t)              \
  (*(src))
#घोषणा TryFromSliceError uint8_t
#घोषणा core_array_TryFromSliceError uint8_t

// Distinguished support for some PartialEq trait implementations
//
// core::cmp::PartialEq<@Array<U, N>> for @Array<T, N>
#घोषणा Eurydice_array_eq(sz, a1, a2, t) \
  (स_भेद((a1)->तथ्य, (a2)->तथ्य, sz * माप(t)) == 0)
// core::cmp::PartialEq<&0 (@Slice<U>)> for @Array<T, N>
#घोषणा Eurydice_array_eq_slice_shared(sz, a1, s2, t, _) \
  (स_भेद((a1)->तथ्य, (s2)->ptr, sz * माप(t)) == 0)
#घोषणा Eurydice_array_eq_slice_mut(sz, a1, s2, t, _) \
  Eurydice_array_eq_slice_shared(sz, a1, s2, t, _)

// DEPRECATED -- should no longer be generated
#घोषणा core_array_equality__core__cmp__PartialEq__Array_U__N___for__Array_T__N___eq( \
    sz, a1, a2, t, _, _ret_t)                                                         \
  Eurydice_array_eq(sz, a1, a2, t)
#घोषणा core_array_equality__core__cmp__PartialEq__0___Slice_U____for__Array_T__N___eq( \
    sz, a1, a2, t, _, _ret_t)                                                           \
  Eurydice_array_eq(sz, a1, ((a2)->ptr), t)
#घोषणा core_cmp_impls__core__cmp__PartialEq__0_mut__B___for__1_mut__A___eq( \
    _m0, _m1, src1, src2, _0, _1, T)                                         \
  Eurydice_slice_eq(src1, src2, _, _, T, _)

#घोषणा Eurydice_slice_split_at(slice, mid, element_type, ret_t)        \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((slice).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((slice).ptr + mid), EURYDICE_CFIELD(.meta =)((slice).meta - mid) \
    }                                                                   \
  }

#घोषणा Eurydice_slice_split_at_mut(slice, mid, element_type, ret_t)    \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((slice).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((slice).ptr + mid), EURYDICE_CFIELD(.meta =)((slice).meta - mid) \
    }                                                                   \
  }

// Conversion of slice to an array, rewritten (by Eurydice) to name the
// destination array, since arrays are not values in C.
// N.B.: see note in karamel/lib/Inlining.ml if you change this.

#घोषणा Eurydice_slice_to_ref_array2(len_, src, arr_ptr, t_ptr, t_arr, t_err, \
                                     t_res)                                   \
  (src.meta >= len_                                                           \
       ? ((t_res){.tag = core_परिणाम_Ok, .val = {.case_Ok = arr_ptr}})        \
       : ((t_res){.tag = core_परिणाम_Err, .val = {.case_Err = 0}}))

// CORE STUFF (conversions, endianness, ...)

// We slap extern "C" on declarations that intend to implement a prototype
// generated by Eurydice, because Eurydice prototypes are always emitted within
// an extern "C" block, UNLESS you use -fcxx17-compat, in which case, you must
// pass -DKRML_CXX17_COMPAT="" to your C++ compiler.
#अगर defined(__cplusplus) && !defined(KRML_CXX17_COMPAT)
बाह्य "C" {
#पूर्ण_अगर

#घोषणा core_hint_black_box(X, _0, _1) (X)

// [ u8; 2 ]
प्रकार काष्ठा Eurydice_array_u8x2_s {
  uint8_t तथ्य[2];
} Eurydice_array_u8x2;

// [ u8; 4 ]
प्रकार काष्ठा Eurydice_array_u8x4_s {
  uint8_t तथ्य[4];
} Eurydice_array_u8x4;

// [ u8; 8 ]
प्रकार काष्ठा Eurydice_array_u8x8_s {
  uint8_t तथ्य[8];
} Eurydice_array_u8x8;

अटल अंतरभूत uint16_t core_अंक_u16_from_le_bytes(Eurydice_array_u8x2 buf) {
  वापस load16_le(buf.तथ्य);
}

अटल अंतरभूत Eurydice_array_u8x4 core_अंक_u32_to_be_bytes(uint32_t src) {
  // TODO: why not store32_be?
  Eurydice_array_u8x4 a;
  uint32_t x = htobe32(src);
  स_नकल(a.तथ्य, &x, 4);
  वापस a;
}

अटल अंतरभूत Eurydice_array_u8x4 core_अंक_u32_to_le_bytes(uint32_t src) {
  Eurydice_array_u8x4 a;
  store32_le(a.तथ्य, src);
  वापस a;
}

अटल अंतरभूत uint32_t core_अंक_u32_from_le_bytes(Eurydice_array_u8x4 buf) {
  वापस load32_le(buf.तथ्य);
}

अटल अंतरभूत Eurydice_array_u8x8 core_अंक_u64_to_le_bytes(uint64_t v) {
  Eurydice_array_u8x8 a;
  store64_le(a.तथ्य, v);
  वापस a;
}

अटल अंतरभूत uint64_t core_अंक_u64_from_le_bytes(Eurydice_array_u8x8 buf) {
  वापस load64_le(buf.तथ्य);
}

अटल अंतरभूत int64_t core_convert_अंक_core_convert_From_i32_for_i64_from(
    int32_t x) {
  वापस x;
}

अटल अंतरभूत uint64_t core_convert_अंक_core_convert_From_u8_for_u64_from(
    uint8_t x) {
  वापस x;
}

अटल अंतरभूत uint64_t core_convert_अंक_core_convert_From_u16_for_u64_from(
    uint16_t x) {
  वापस x;
}

अटल अंतरभूत माप_प्रकार core_convert_अंक_core_convert_From_u16_for_usize_from(
    uint16_t x) {
  वापस x;
}

अटल अंतरभूत uint32_t core_अंक_u8_गिनती_ones(uint8_t x0) {
#अगर_घोषित _MSC_VER
  वापस __popcnt(x0);
#अन्यथा
  वापस __builtin_popcount(x0);
#पूर्ण_अगर
}

अटल अंतरभूत uint32_t core_अंक_u32_गिनती_ones(uint32_t x0) {
#अगर_घोषित _MSC_VER
  वापस __popcnt(x0);
#अन्यथा
  वापस __builtin_popcount(x0);
#पूर्ण_अगर
}

अटल अंतरभूत uint32_t core_अंक_i32_गिनती_ones(int32_t x0) {
#अगर_घोषित _MSC_VER
  वापस __popcnt(x0);
#अन्यथा
  वापस __builtin_popcount(x0);
#पूर्ण_अगर
}

अटल अंतरभूत माप_प्रकार core_cmp_impls__core__cmp__Ord_for_usize__min(माप_प्रकार a,
                                                                   माप_प्रकार b) {
  अगर (a <= b)
    वापस a;
  अन्यथा
    वापस b;
}

// unsigned overflow wraparound semantics in C
अटल अंतरभूत uint8_t core_अंक_u8_wrapping_sub(uint8_t x, uint8_t y) {
  वापस x - y;
}
अटल अंतरभूत uint8_t core_अंक_u8_wrapping_add(uint8_t x, uint8_t y) {
  वापस x + y;
}
अटल अंतरभूत uint8_t core_अंक_u8_wrapping_mul(uint8_t x, uint8_t y) {
  वापस x * y;
}
अटल अंतरभूत uint16_t core_अंक_u16_wrapping_sub(uint16_t x, uint16_t y) {
  वापस x - y;
}
अटल अंतरभूत uint16_t core_अंक_u16_wrapping_add(uint16_t x, uint16_t y) {
  वापस x + y;
}
अटल अंतरभूत uint16_t core_अंक_u16_wrapping_mul(uint16_t x, uint16_t y) {
  वापस x * y;
}
अटल अंतरभूत uint32_t core_अंक_u32_wrapping_sub(uint32_t x, uint32_t y) {
  वापस x - y;
}
अटल अंतरभूत uint32_t core_अंक_u32_wrapping_add(uint32_t x, uint32_t y) {
  वापस x + y;
}
अटल अंतरभूत uint32_t core_अंक_u32_wrapping_mul(uint32_t x, uint32_t y) {
  वापस x * y;
}
अटल अंतरभूत uint64_t core_अंक_u64_wrapping_sub(uint64_t x, uint64_t y) {
  वापस x - y;
}
अटल अंतरभूत uint64_t core_अंक_u64_wrapping_add(uint64_t x, uint64_t y) {
  वापस x + y;
}
अटल अंतरभूत uint64_t core_अंक_u64_wrapping_mul(uint64_t x, uint64_t y) {
  वापस x * y;
}
अटल अंतरभूत माप_प्रकार core_अंक_usize_wrapping_sub(माप_प्रकार x, माप_प्रकार y) {
  वापस x - y;
}
अटल अंतरभूत माप_प्रकार core_अंक_usize_wrapping_add(माप_प्रकार x, माप_प्रकार y) {
  वापस x + y;
}
अटल अंतरभूत माप_प्रकार core_अंक_usize_wrapping_mul(माप_प्रकार x, माप_प्रकार y) {
  वापस x * y;
}

अटल अंतरभूत int8_t core_अंक_i8_wrapping_add(int8_t x, int8_t y) {
  वापस (int8_t)((uint8_t)x + (uint8_t)y);
}
अटल अंतरभूत int8_t core_अंक_i8_wrapping_sub(int8_t x, int8_t y) {
  वापस (int8_t)((uint8_t)x - (uint8_t)y);
}
अटल अंतरभूत int8_t core_अंक_i8_wrapping_mul(int8_t x, int8_t y) {
  वापस (int8_t)((uint8_t)x * (uint8_t)y);
}
अटल अंतरभूत int16_t core_अंक_i16_wrapping_add(int16_t x, int16_t y) {
  वापस (int16_t)((uint16_t)x + (uint16_t)y);
}
अटल अंतरभूत int16_t core_अंक_i16_wrapping_sub(int16_t x, int16_t y) {
  वापस (int16_t)((uint16_t)x - (uint16_t)y);
}
अटल अंतरभूत int16_t core_अंक_i16_wrapping_mul(int16_t x, int16_t y) {
  वापस (int16_t)((uint16_t)x * (uint16_t)y);
}
अटल अंतरभूत int32_t core_अंक_i32_wrapping_add(int32_t x, int32_t y) {
  वापस (int32_t)((uint32_t)x + (uint32_t)y);
}
अटल अंतरभूत int32_t core_अंक_i32_wrapping_sub(int32_t x, int32_t y) {
  वापस (int32_t)((uint32_t)x - (uint32_t)y);
}
अटल अंतरभूत int32_t core_अंक_i32_wrapping_mul(int32_t x, int32_t y) {
  वापस (int32_t)((uint32_t)x * (uint32_t)y);
}
अटल अंतरभूत int64_t core_अंक_i64_wrapping_add(int64_t x, int64_t y) {
  वापस (int64_t)((uint64_t)x + (uint64_t)y);
}
अटल अंतरभूत int64_t core_अंक_i64_wrapping_sub(int64_t x, int64_t y) {
  वापस (int64_t)((uint64_t)x - (uint64_t)y);
}
अटल अंतरभूत int64_t core_अंक_i64_wrapping_mul(int64_t x, int64_t y) {
  वापस (int64_t)((uint64_t)x * (uint64_t)y);
}
अटल अंतरभूत int8_t core_अंक_i8_wrapping_neg(int8_t x) {
  वापस (int8_t)(-(uint8_t)x);
}
अटल अंतरभूत int16_t core_अंक_i16_wrapping_neg(int16_t x) {
  वापस (int16_t)(-(uint16_t)x);
}
अटल अंतरभूत int32_t core_अंक_i32_wrapping_neg(int32_t x) {
  वापस (int32_t)(-(uint32_t)x);
}
अटल अंतरभूत int64_t core_अंक_i64_wrapping_neg(int64_t x) {
  वापस (int64_t)(-(uint64_t)x);
}

अटल अंतरभूत uint64_t core_अंक_u64_rotate_बायाँ(uint64_t x0, uint32_t x1) {
  वापस (x0 << x1) | (x0 >> ((-x1) & 63));
}

अटल अंतरभूत व्योम core_ops_arith__i32__add_assign(int32_t *x0, int32_t *x1) {
  *x0 = *x0 + *x1;
}

अटल अंतरभूत uint8_t Eurydice_bitand_pv_u8(स्थिर uint8_t *p, uint8_t v) {
  वापस (*p) & v;
}
अटल अंतरभूत uint8_t Eurydice_shr_pv_u8(स्थिर uint8_t *p, int32_t v) {
  वापस (*p) >> v;
}
अटल अंतरभूत uint32_t Eurydice_min_u32(uint32_t x, uint32_t y) {
  वापस x < y ? x : y;
}

अटल अंतरभूत uint8_t
core_ops_bit__core__ops__bit__BitAnd_u8__u8__for__0__u8___bitand(
    स्थिर uint8_t *x0, uint8_t x1) {
  वापस Eurydice_bitand_pv_u8(x0, x1);
}

अटल अंतरभूत uint8_t
core_ops_bit__core__ops__bit__Shr_i32__u8__for__0__u8___shr(स्थिर uint8_t *x0,
                                                            int32_t x1) {
  वापस Eurydice_shr_pv_u8(x0, x1);
}

#घोषणा core_अंक_nonzero_private_Non_Zero_Usize_Inner माप_प्रकार
अटल अंतरभूत core_अंक_nonzero_private_Non_Zero_Usize_Inner
core_अंक_nonzero_private_core_clone_Clone_for_core_अंक_nonzero_private_Non_Zero_Usize_Inner_clone(
    core_अंक_nonzero_private_Non_Zero_Usize_Inner *x0) {
  वापस *x0;
}

#अगर defined(__cplusplus) && !defined(KRML_CXX17_COMPAT)
}
#पूर्ण_अगर

// ITERATORS

#घोषणा Eurydice_range_iter_अग्र(iter_ptr, t, ret_t)      \
  (((iter_ptr)->start >= (iter_ptr)->end)                 \
       ? (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.tag =) 0, \
                               EURYDICE_CFIELD(.f0 =) 0}) \
       : (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.tag =) 1, \
                               EURYDICE_CFIELD(.f0 =)(iter_ptr)->start++}))

#घोषणा core_iter_range_core_iter_traits_iterator_Iterator_A_for_core_ops_range_Range_A_Trait_Clause_0_अग्र \
  Eurydice_range_iter_अग्र

// See note in karamel/lib/Inlining.ml if you change this
#घोषणा Eurydice_into_iter(x, t, _ret_t, _) (x)
#घोषणा core_iter_traits_collect__core__iter__traits__collect__IntoIterator_Clause1_Item__I__for_I__into_iter \
  Eurydice_into_iter

// STRINGS

प्रकार अक्षर Eurydice_c_char_t;
प्रकार स्थिर Eurydice_c_char_t *Prims_string;
प्रकार व्योम Eurydice_c_void_t;

// UNSAFE CODE

#घोषणा core_slice___Slice_T___as_mut_ptr(x, t, _) (x.ptr)
#घोषणा core_mem_आकार_of(t, _) (माप(t))
#घोषणा core_slice_raw_from_raw_parts_mut(ptr, len, _0, _1) \
  (KRML_CLITERAL(Eurydice_slice){(व्योम *)(ptr), len})
#घोषणा core_slice_raw_from_raw_parts(ptr, len, _0, _1) \
  (KRML_CLITERAL(Eurydice_slice){(व्योम *)(ptr), len})

// FIXME: add dedicated extraction to extract NonNull<T> as T*
#घोषणा core_ptr_non_null_NonNull व्योम *

// PRINTING
//
// This is temporary. Ultimately we want to be able to extract all of this.

प्रकार व्योम *core_fmt_Formatter;
#घोषणा core_fmt_rt__core__fmt__rt__Argument__a___new_display(x1, x2, x3, x4) \
  शून्य

// BOXES

#अगर_अघोषित EURYDICE_MALLOC
#घोषणा EURYDICE_MALLOC दो_स्मृति
#पूर्ण_अगर

#अगर_अघोषित EURYDICE_REALLOC
#घोषणा EURYDICE_REALLOC पुनः_स्मृति
#पूर्ण_अगर

अटल अंतरभूत अक्षर *malloc_and_init(माप_प्रकार sz, अक्षर *init) {
  अक्षर *ptr = (अक्षर *)EURYDICE_MALLOC(sz);
  अगर (ptr != शून्य) स_नकल(ptr, init, sz);
  वापस ptr;
}

#घोषणा Eurydice_box_new(init, t, t_dst) \
  ((t_dst)(malloc_and_init(माप(t), (अक्षर *)(&init))))

// Initializer for array of size zero
#घोषणा Eurydice_empty_array(dummy, t, t_dst) ((t_dst){.तथ्य = {}})

#घोषणा Eurydice_box_new_array(len, ptr, t, t_dst) \
  ((t_dst)(malloc_and_init(len * माप(t), (अक्षर *)(ptr))))

// FIXME this needs to handle allocation failure errors, but this seems hard to
// do without evaluating malloc_and_init twice...
#घोषणा alloc_boxed__alloc__boxed__Box_T___try_new(init, t, t_ret) \
  ((t_ret){.tag = core_परिणाम_Ok,                                  \
           .f0 = (t *)malloc_and_init(माप(t), (अक्षर *)(&init))})

// OPTIONS

#घोषणा core_option__core__option__Option_T__TraitClause_0___is_some( \
    x, _of_type, _)                                                   \
  x->tag

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


#अगर_अघोषित combined_core_H
#घोषणा combined_core_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर

अटल अंतरभूत uint32_t core_अंक_i32_गिनती_ones(int32_t x0);

अटल अंतरभूत uint16_t core_अंक_u16_wrapping_add(uint16_t x0, uint16_t x1);

अटल अंतरभूत uint64_t core_अंक_u64_from_le_bytes(Eurydice_array_u8x8 x0);

अटल अंतरभूत uint64_t core_अंक_u64_rotate_बायाँ(uint64_t x0, uint32_t x1);

अटल अंतरभूत Eurydice_array_u8x8 core_अंक_u64_to_le_bytes(uint64_t x0);

अटल अंतरभूत uint32_t core_अंक_u8_गिनती_ones(uint8_t x0);

अटल अंतरभूत uint8_t core_अंक_u8_wrapping_sub(uint8_t x0, uint8_t x1);

अटल अंतरभूत uint8_t
core_ops_bit__core__ops__bit__BitAnd_u8__u8__for__0__u8___bitand(स्थिर uint8_t *x0, uint8_t x1);

अटल अंतरभूत uint8_t
core_ops_bit__core__ops__bit__Shr_i32__u8__for__0__u8___shr(स्थिर uint8_t *x0, int32_t x1);

/**
A monomorphic instance of core.ops.range.Range
with types size_t

*/
प्रकार काष्ठा core_ops_range_Range_87_s
{
  माप_प्रकार start;
  माप_प्रकार end;
}
core_ops_range_Range_87;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
अटल अंतरभूत Eurydice_mut_borrow_slice_i16
Eurydice_slice_subslice_mut_a6(Eurydice_mut_borrow_slice_i16 s, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_i16){
        .ptr = s.ptr + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $16size_t
*/
प्रकार काष्ठा Eurydice_arr_b2_s { uint8_t तथ्य[16U]; } Eurydice_arr_b2;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_b2
with const generics
- $256size_t
*/
प्रकार काष्ठा Eurydice_arr_87_s { Eurydice_arr_b2 तथ्य[256U]; } Eurydice_arr_87;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $24size_t
*/
प्रकार काष्ठा Eurydice_arr_94_s { uint8_t तथ्य[24U]; } Eurydice_arr_94;

#घोषणा core_परिणाम_Ok 0
#घोषणा core_परिणाम_Err 1

प्रकार uint8_t core_परिणाम_परिणाम_57_tags;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_94, core_array_TryFromSliceError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_57_s
{
  core_परिणाम_परिणाम_57_tags tag;
  जोड़ {
    Eurydice_arr_94 case_Ok;
    core_array_TryFromSliceError case_Err;
  }
  val;
}
core_परिणाम_परिणाम_57;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$24size_t]], core_array_TryFromSliceError

*/
अटल अंतरभूत Eurydice_arr_94 core_परिणाम_unwrap_26_78(core_परिणाम_परिणाम_57 self)
{
  अगर (self.tag == core_परिणाम_Ok)
  {
    वापस self.val.case_Ok;
  }
  अन्यथा
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $16size_t
*/
प्रकार काष्ठा Eurydice_arr_d6_s { int16_t तथ्य[16U]; } Eurydice_arr_d6;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $20size_t
*/
प्रकार काष्ठा Eurydice_arr_fc_s { uint8_t तथ्य[20U]; } Eurydice_arr_fc;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_fc, core_array_TryFromSliceError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_83_s
{
  core_परिणाम_परिणाम_57_tags tag;
  जोड़ {
    Eurydice_arr_fc case_Ok;
    core_array_TryFromSliceError case_Err;
  }
  val;
}
core_परिणाम_परिणाम_83;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$20size_t]], core_array_TryFromSliceError

*/
अटल अंतरभूत Eurydice_arr_fc core_परिणाम_unwrap_26_7d(core_परिणाम_परिणाम_83 self)
{
  अगर (self.tag == core_परिणाम_Ok)
  {
    वापस self.val.case_Ok;
  }
  अन्यथा
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1184size_t
*/
प्रकार काष्ठा Eurydice_arr_5f_s { uint8_t तथ्य[1184U]; } Eurydice_arr_5f;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_from_shared_5f2(स्थिर Eurydice_arr_5f *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_to_shared_210(स्थिर Eurydice_arr_5f *a, माप_प्रकार r)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = r;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2400size_t
*/
प्रकार काष्ठा Eurydice_arr_7d_s { uint8_t तथ्य[2400U]; } Eurydice_arr_7d;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d48(स्थिर Eurydice_arr_7d *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1152size_t
*/
प्रकार काष्ठा Eurydice_arr_0e_s { uint8_t तथ्य[1152U]; } Eurydice_arr_0e;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1152
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_f4(स्थिर Eurydice_arr_0e *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1152U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d417(Eurydice_arr_7d *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1152
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_f4(Eurydice_arr_0e *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1152U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_5f4(Eurydice_arr_5f *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d416(Eurydice_arr_5f *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 24
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_ed(स्थिर Eurydice_arr_94 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)24U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $384size_t
*/
प्रकार काष्ठा Eurydice_arr_b20_s { uint8_t तथ्य[384U]; } Eurydice_arr_b20;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 384
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d415(Eurydice_arr_b20 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 384
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_a9(स्थिर Eurydice_arr_b20 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)384U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $32size_t
*/
प्रकार काष्ठा Eurydice_arr_ec_s { uint8_t तथ्य[32U]; } Eurydice_arr_ec;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_ec, core_array_TryFromSliceError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_07_s
{
  core_परिणाम_परिणाम_57_tags tag;
  जोड़ {
    Eurydice_arr_ec case_Ok;
    core_array_TryFromSliceError case_Err;
  }
  val;
}
core_परिणाम_परिणाम_07;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$32size_t]], core_array_TryFromSliceError

*/
अटल अंतरभूत Eurydice_arr_ec core_परिणाम_unwrap_26_39(core_परिणाम_परिणाम_07 self)
{
  अगर (self.tag == core_परिणाम_Ok)
  {
    वापस self.val.case_Ok;
  }
  अन्यथा
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $64size_t
*/
प्रकार काष्ठा Eurydice_arr_c7_s { uint8_t तथ्य[64U]; } Eurydice_arr_c7;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_from_shared_5f1(स्थिर Eurydice_arr_c7 *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d47(स्थिर Eurydice_arr_c7 *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1184
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_ff(स्थिर Eurydice_arr_5f *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1184U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1088size_t
*/
प्रकार काष्ठा Eurydice_arr_2b_s { uint8_t तथ्य[1088U]; } Eurydice_arr_2b;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_5f3(Eurydice_arr_2b *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d414(Eurydice_arr_2b *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 20
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_8f(स्थिर Eurydice_arr_fc *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)20U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $320size_t
*/
प्रकार काष्ठा Eurydice_arr_b0_s { uint8_t तथ्य[320U]; } Eurydice_arr_b0;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 320
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d413(Eurydice_arr_b0 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 320
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_56(स्थिर Eurydice_arr_b0 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)320U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $256size_t
*/
प्रकार काष्ठा Eurydice_arr_04_s { int16_t तथ्य[256U]; } Eurydice_arr_04;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int16_t
with const generics
- N= 256
*/
अटल अंतरभूत Eurydice_borrow_slice_i16
Eurydice_array_to_slice_shared_99(स्थिर Eurydice_arr_04 *a)
{
  Eurydice_borrow_slice_i16 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)256U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $128size_t
*/
प्रकार काष्ठा Eurydice_arr_89_s { uint8_t तथ्य[128U]; } Eurydice_arr_89;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_89
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_58_s { Eurydice_arr_89 तथ्य[3U]; } Eurydice_arr_58;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $33size_t
*/
प्रकार काष्ठा Eurydice_arr_fa0_s { uint8_t तथ्य[33U]; } Eurydice_arr_fa0;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 33
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_b5(स्थिर Eurydice_arr_fa0 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)33U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_fa0
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_fd_s { Eurydice_arr_fa0 तथ्य[3U]; } Eurydice_arr_fd;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 33
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d412(Eurydice_arr_fa0 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $272size_t
*/
प्रकार काष्ठा Eurydice_arr_5b_s { int16_t तथ्य[272U]; } Eurydice_arr_5b;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
अटल अंतरभूत Eurydice_borrow_slice_i16
Eurydice_array_to_subslice_shared_e70(स्थिर Eurydice_arr_5b *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_i16){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $168size_t
*/
प्रकार काष्ठा Eurydice_arr_c5_s { uint8_t तथ्य[168U]; } Eurydice_arr_c5;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d46(स्थिर Eurydice_arr_c5 *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_2c_s { Eurydice_arr_c5 तथ्य[3U]; } Eurydice_arr_2c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_5b
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_b1_s { Eurydice_arr_5b तथ्य[3U]; } Eurydice_arr_b1;

/**
A monomorphic instance of Eurydice.arr
with types size_t
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_eb_s { माप_प्रकार तथ्य[3U]; } Eurydice_arr_eb;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_i16
Eurydice_array_to_subslice_mut_e7(Eurydice_arr_5b *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_i16){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $504size_t
*/
प्रकार काष्ठा Eurydice_arr_79_s { uint8_t तथ्य[504U]; } Eurydice_arr_79;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 504
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d45(स्थिर Eurydice_arr_79 *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_79
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_7e_s { Eurydice_arr_79 तथ्य[3U]; } Eurydice_arr_7e;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 504
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_48(Eurydice_arr_79 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)504U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $34size_t
*/
प्रकार काष्ठा Eurydice_arr_31_s { uint8_t तथ्य[34U]; } Eurydice_arr_31;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_31
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_810_s { Eurydice_arr_31 तथ्य[3U]; } Eurydice_arr_810;

/**
A monomorphic instance of Eurydice.slice_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t

*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_slice_subslice_from_shared_6d(Eurydice_borrow_slice_u8 s, माप_प्रकार r)
{
  वापस (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = s.ptr + r, .meta = s.meta - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1120size_t
*/
प्रकार काष्ठा Eurydice_arr_af_s { uint8_t तथ्य[1120U]; } Eurydice_arr_af;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1120
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_81(स्थिर Eurydice_arr_af *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1120U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1088
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_06(स्थिर Eurydice_arr_2b *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1088U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_5f2(Eurydice_arr_af *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)1120U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d411(Eurydice_arr_af *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_5f1(Eurydice_arr_c7 *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d410(Eurydice_arr_c7 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_from_shared_5f0(स्थिर Eurydice_arr_2b *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d44(स्थिर Eurydice_arr_2b *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2400
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_51(स्थिर Eurydice_arr_7d *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)2400U;
  वापस lit;
}

प्रकार काष्ठा int16_t_x2_s
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
अटल KRML_MUSTINLINE Eurydice_arr_94
libcrux_secrets_int_public_integers_declassify_d8_40(Eurydice_arr_94 self)
{
  वापस self;
}

प्रकार काष्ठा uint8_t_x3_s
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
अटल KRML_MUSTINLINE Eurydice_arr_fc
libcrux_secrets_int_public_integers_declassify_d8_2b(Eurydice_arr_fc self)
{
  वापस self;
}

प्रकार काष्ठा uint8_t_x5_s
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
अटल KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_secrets_int_public_integers_declassify_d8_52(Eurydice_array_u8x8 self)
{
  वापस self;
}

प्रकार काष्ठा uint8_t_x4_s
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
अटल KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_secrets_int_public_integers_declassify_d8_75(Eurydice_array_u8x2 self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types Eurydice_arr int16_t[[$16size_t]]

*/
अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_secrets_int_public_integers_classify_27_4b(Eurydice_arr_d6 self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a ([T])> for &'a ([T])}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_6d
with types uint8_t

*/
अटल KRML_MUSTINLINE Eurydice_borrow_slice_u8
libcrux_secrets_int_classify_public_classify_ref_6d_90(Eurydice_borrow_slice_u8 self)
{
  वापस self;
}

प्रकार काष्ठा int16_t_x8_s
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
अटल अंतरभूत Eurydice_borrow_slice_i16
Eurydice_array_to_subslice_shared_e7(स्थिर Eurydice_arr_d6 *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_i16){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a ([T])> for &'a ([T])}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_6d
with types int16_t

*/
अटल KRML_MUSTINLINE Eurydice_borrow_slice_i16
libcrux_secrets_int_classify_public_classify_ref_6d_39(Eurydice_borrow_slice_i16 self)
{
  वापस self;
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
अटल अंतरभूत Eurydice_borrow_slice_i16
Eurydice_slice_subslice_shared_a6(Eurydice_borrow_slice_i16 s, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_i16){ .ptr = s.ptr + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_d6, core_array_TryFromSliceError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_ec_s
{
  core_परिणाम_परिणाम_57_tags tag;
  जोड़ {
    Eurydice_arr_d6 case_Ok;
    core_array_TryFromSliceError case_Err;
  }
  val;
}
core_परिणाम_परिणाम_ec;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr int16_t[[$16size_t]], core_array_TryFromSliceError

*/
अटल अंतरभूत Eurydice_arr_d6 core_परिणाम_unwrap_26_d3(core_परिणाम_परिणाम_ec self)
{
  अगर (self.tag == core_परिणाम_Ok)
  {
    वापस self.val.case_Ok;
  }
  अन्यथा
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $128size_t
*/
प्रकार काष्ठा Eurydice_arr_34_s { int16_t तथ्य[128U]; } Eurydice_arr_34;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d43(स्थिर Eurydice_arr_94 *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d49(Eurydice_arr_94 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 16
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_29(Eurydice_arr_b2 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)16U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d42(स्थिर Eurydice_arr_b2 *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d48(Eurydice_arr_b2 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $19size_t
*/
प्रकार काष्ठा Eurydice_arr_38_s { uint8_t तथ्य[19U]; } Eurydice_arr_38;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d41(स्थिर Eurydice_arr_38 *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d47(Eurydice_arr_38 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types int32_t, size_t

*/
प्रकार काष्ठा Eurydice_dst_ref_mut_83_s
{
  int32_t *ptr;
  माप_प्रकार meta;
}
Eurydice_dst_ref_mut_83;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
अटल अंतरभूत Eurydice_dst_ref_mut_83
Eurydice_slice_subslice_mut_47(Eurydice_dst_ref_mut_83 s, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = s.ptr + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 16
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_29(स्थिर Eurydice_arr_b2 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)16U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_b2
with const generics
- $16size_t
*/
प्रकार काष्ठा Eurydice_arr_a30_s { Eurydice_arr_b2 तथ्य[16U]; } Eurydice_arr_a30;

/**
A monomorphic instance of Eurydice.array_to_subslice_to_mut
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_to_mut_21(Eurydice_arr_ec *a, माप_प्रकार r)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = r;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4627size_t
*/
प्रकार काष्ठा Eurydice_arr_93_s { uint8_t तथ्य[4627U]; } Eurydice_arr_93;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4627
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_11(स्थिर Eurydice_arr_93 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4627U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2592size_t
*/
प्रकार काष्ठा Eurydice_arr_43_s { uint8_t तथ्य[2592U]; } Eurydice_arr_43;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2592
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_fc(स्थिर Eurydice_arr_43 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)2592U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4896size_t
*/
प्रकार काष्ठा Eurydice_arr_e2_s { uint8_t तथ्य[4896U]; } Eurydice_arr_e2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4896
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_f7(स्थिर Eurydice_arr_e2 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4896U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $256size_t
*/
प्रकार काष्ठा Eurydice_arr_6c_s { int32_t तथ्य[256U]; } Eurydice_arr_6c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $8size_t
*/
प्रकार काष्ठा Eurydice_arr_81_s { Eurydice_arr_6c तथ्य[8U]; } Eurydice_arr_81;

#घोषणा core_option_None 0
#घोषणा core_option_Some 1

प्रकार uint8_t core_option_Option_45_tags;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_81

*/
प्रकार काष्ठा core_option_Option_45_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_81 f0;
}
core_option_Option_45;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_c7

*/
प्रकार काष्ठा core_option_Option_b2_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_c7 f0;
}
core_option_Option_b2;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4627
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_11(Eurydice_arr_93 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4627U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_6c, size_t

*/
प्रकार काष्ठा Eurydice_dst_ref_shared_20_s
{
  स्थिर Eurydice_arr_6c *ptr;
  माप_प्रकार meta;
}
Eurydice_dst_ref_shared_20;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 8
*/
अटल अंतरभूत Eurydice_dst_ref_shared_20
Eurydice_array_to_slice_shared_861(स्थिर Eurydice_arr_81 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)8U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_6c, size_t

*/
प्रकार काष्ठा Eurydice_dst_ref_mut_20_s
{
  Eurydice_arr_6c *ptr;
  माप_प्रकार meta;
}
Eurydice_dst_ref_mut_20;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 8
*/
अटल अंतरभूत Eurydice_dst_ref_mut_20 Eurydice_array_to_slice_mut_861(Eurydice_arr_81 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)8U;
  वापस lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$64size_t]]

*/
अटल KRML_MUSTINLINE व्योम
libcrux_secrets_mem_requests_ct_declassify_56(स्थिर Eurydice_arr_c7 *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1024size_t
*/
प्रकार काष्ठा Eurydice_arr_1b_s { uint8_t तथ्य[1024U]; } Eurydice_arr_1b;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1024
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_68(स्थिर Eurydice_arr_1b *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1024U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1024
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_68(Eurydice_arr_1b *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1024U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2592
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_fc(Eurydice_arr_43 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)2592U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4896
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_f7(Eurydice_arr_e2 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4896U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $3309size_t
*/
प्रकार काष्ठा Eurydice_arr_0c_s { uint8_t तथ्य[3309U]; } Eurydice_arr_0c;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 3309
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_6b(स्थिर Eurydice_arr_0c *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)3309U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1952size_t
*/
प्रकार काष्ठा Eurydice_arr_29_s { uint8_t तथ्य[1952U]; } Eurydice_arr_29;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1952
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_37(स्थिर Eurydice_arr_29 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1952U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4032size_t
*/
प्रकार काष्ठा Eurydice_arr_24_s { uint8_t तथ्य[4032U]; } Eurydice_arr_24;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4032
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_98(स्थिर Eurydice_arr_24 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4032U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $6size_t
*/
प्रकार काष्ठा Eurydice_arr_5d0_s { Eurydice_arr_6c तथ्य[6U]; } Eurydice_arr_5d0;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_5d0

*/
प्रकार काष्ठा core_option_Option_05_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_5d0 f0;
}
core_option_Option_05;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $48size_t
*/
प्रकार काष्ठा Eurydice_arr_65_s { uint8_t तथ्य[48U]; } Eurydice_arr_65;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_65

*/
प्रकार काष्ठा core_option_Option_81_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_65 f0;
}
core_option_Option_81;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 3309
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_6b(Eurydice_arr_0c *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)3309U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
अटल अंतरभूत Eurydice_dst_ref_shared_20
Eurydice_array_to_slice_shared_860(स्थिर Eurydice_arr_5d0 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)6U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
अटल अंतरभूत Eurydice_dst_ref_mut_20 Eurydice_array_to_slice_mut_860(Eurydice_arr_5d0 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)6U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 48
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_9f0(स्थिर Eurydice_arr_65 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)48U;
  वापस lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$48size_t]]

*/
अटल KRML_MUSTINLINE व्योम
libcrux_secrets_mem_requests_ct_declassify_69(स्थिर Eurydice_arr_65 *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1952
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_37(Eurydice_arr_29 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1952U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4032
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_98(Eurydice_arr_24 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4032U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2420size_t
*/
प्रकार काष्ठा Eurydice_arr_85_s { uint8_t तथ्य[2420U]; } Eurydice_arr_85;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2420
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_0d(स्थिर Eurydice_arr_85 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)2420U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1312size_t
*/
प्रकार काष्ठा Eurydice_arr_02_s { uint8_t तथ्य[1312U]; } Eurydice_arr_02;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1312
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_9f(स्थिर Eurydice_arr_02 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1312U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2560size_t
*/
प्रकार काष्ठा Eurydice_arr_10_s { uint8_t तथ्य[2560U]; } Eurydice_arr_10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2560
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_34(स्थिर Eurydice_arr_10 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)2560U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $4size_t
*/
प्रकार काष्ठा Eurydice_arr_b7_s { Eurydice_arr_6c तथ्य[4U]; } Eurydice_arr_b7;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_b7

*/
प्रकार काष्ठा core_option_Option_51_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_b7 f0;
}
core_option_Option_51;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_ec

*/
प्रकार काष्ठा core_option_Option_14_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_ec f0;
}
core_option_Option_14;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2420
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_0d(Eurydice_arr_85 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)2420U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 4
*/
अटल अंतरभूत Eurydice_dst_ref_shared_20
Eurydice_array_to_slice_shared_86(स्थिर Eurydice_arr_b7 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 4
*/
अटल अंतरभूत Eurydice_dst_ref_mut_20 Eurydice_array_to_slice_mut_86(Eurydice_arr_b7 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 256
*/
अटल अंतरभूत Eurydice_dst_ref_mut_83
Eurydice_array_to_subslice_mut_44(Eurydice_arr_6c *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types int32_t, size_t

*/
प्रकार काष्ठा Eurydice_dst_ref_shared_83_s
{
  स्थिर int32_t *ptr;
  माप_प्रकार meta;
}
Eurydice_dst_ref_shared_83;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 256
*/
अटल अंतरभूत Eurydice_dst_ref_shared_83
Eurydice_array_to_slice_shared_af(स्थिर Eurydice_arr_6c *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)256U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $136size_t
*/
प्रकार काष्ठा Eurydice_arr_ff_s { uint8_t तथ्य[136U]; } Eurydice_arr_ff;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_from_shared_5f(स्थिर Eurydice_arr_ff *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d40(स्थिर Eurydice_arr_ff *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$32size_t]]

*/
अटल KRML_MUSTINLINE व्योम
libcrux_secrets_mem_requests_ct_declassify_4b(स्थिर Eurydice_arr_ec *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $768size_t
*/
प्रकार काष्ठा Eurydice_arr_d2_s { uint8_t तथ्य[768U]; } Eurydice_arr_d2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 768
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_27(स्थिर Eurydice_arr_d2 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)768U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 768
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_27(Eurydice_arr_d2 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)768U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $640size_t
*/
प्रकार काष्ठा Eurydice_arr_20_s { uint8_t तथ्य[640U]; } Eurydice_arr_20;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 640
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_4f(स्थिर Eurydice_arr_20 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)640U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 640
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_4f(Eurydice_arr_20 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)640U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $576size_t
*/
प्रकार काष्ठा Eurydice_arr_220_s { uint8_t तथ्य[576U]; } Eurydice_arr_220;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 576
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_8a(स्थिर Eurydice_arr_220 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)576U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 576
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_8a(Eurydice_arr_220 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)576U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $11size_t
*/
प्रकार काष्ठा Eurydice_arr_c9_s { uint8_t तथ्य[11U]; } Eurydice_arr_c9;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 11
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_2f(स्थिर Eurydice_arr_c9 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)11U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1size_t
*/
प्रकार काष्ठा Eurydice_arr_82_s { uint8_t तथ्य[1U]; } Eurydice_arr_82;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_79(स्थिर Eurydice_arr_82 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1U;
  वापस lit;
}

/**
 Mark memory as secret.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_classify
with types Eurydice_derefed_slice uint8_t

*/
अटल KRML_MUSTINLINE व्योम libcrux_secrets_mem_requests_ct_classify_45(स्थिर uint8_t (*val)[])
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1312
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_9f0(Eurydice_arr_02 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)1312U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2560
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_34(Eurydice_arr_10 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)2560U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 64
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_17(स्थिर Eurydice_arr_c7 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)64U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $263size_t
*/
प्रकार काष्ठा Eurydice_arr_d0_s { int32_t तथ्य[263U]; } Eurydice_arr_d0;

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_d0, size_t

*/
प्रकार काष्ठा Eurydice_dst_ref_mut_33_s
{
  Eurydice_arr_d0 *ptr;
  माप_प्रकार meta;
}
Eurydice_dst_ref_mut_33;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_d0
with const generics
- $4size_t
*/
प्रकार काष्ठा Eurydice_arr_930_s { Eurydice_arr_d0 तथ्य[4U]; } Eurydice_arr_930;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$263size_t]]
with const generics
- N= 4
*/
अटल अंतरभूत Eurydice_dst_ref_mut_33 Eurydice_array_to_slice_mut_7e(Eurydice_arr_930 *a)
{
  Eurydice_dst_ref_mut_33 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_d0, size_t

*/
प्रकार काष्ठा Eurydice_dst_ref_shared_33_s
{
  स्थिर Eurydice_arr_d0 *ptr;
  माप_प्रकार meta;
}
Eurydice_dst_ref_shared_33;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $840size_t
*/
प्रकार काष्ठा Eurydice_arr_d10_s { uint8_t तथ्य[840U]; } Eurydice_arr_d10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 840
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_4c(स्थिर Eurydice_arr_d10 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)840U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 34
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_e9(स्थिर Eurydice_arr_31 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)34U;
  वापस lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_derefed_slice uint8_t

*/
अटल KRML_MUSTINLINE व्योम
libcrux_secrets_mem_requests_ct_declassify_45(स्थिर uint8_t (*val)[])
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 263
*/
अटल अंतरभूत Eurydice_dst_ref_shared_83
Eurydice_array_to_slice_shared_2c0(स्थिर Eurydice_arr_d0 *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)263U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types int32_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 263
*/
अटल अंतरभूत Eurydice_dst_ref_mut_83
Eurydice_array_to_subslice_from_mut_11(Eurydice_arr_d0 *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)263U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $66size_t
*/
प्रकार काष्ठा Eurydice_arr_91_s { uint8_t तथ्य[66U]; } Eurydice_arr_91;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 66
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_f1(स्थिर Eurydice_arr_91 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)66U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 128
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_78(स्थिर Eurydice_arr_89 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)128U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 128
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_78(Eurydice_arr_89 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)128U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_82(स्थिर Eurydice_array_u8x2 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)2U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 32
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_01(स्थिर Eurydice_arr_ec *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)32U;
  वापस lit;
}

/**
 Mark memory as secret.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_classify
with types Eurydice_arr uint8_t[[$32size_t]]

*/
अटल KRML_MUSTINLINE व्योम
libcrux_secrets_mem_requests_ct_classify_4b(स्थिर Eurydice_arr_ec *val)
{

}

प्रकार काष्ठा Eurydice_arr_c5_x4_s
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
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_2c(Eurydice_arr_c5 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)168U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 840
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_4c(Eurydice_arr_d10 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)840U;
  वापस lit;
}

प्रकार काष्ठा Eurydice_arr_ff_x4_s
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
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_58(Eurydice_arr_ff *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)136U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_shared_d4(स्थिर Eurydice_arr_ec *a, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_ff
with const generics
- $4size_t
*/
प्रकार काष्ठा Eurydice_arr_dc0_s { Eurydice_arr_ff तथ्य[4U]; } Eurydice_arr_dc0;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $4size_t
*/
प्रकार काष्ठा Eurydice_arr_9c_s { Eurydice_arr_c5 तथ्य[4U]; } Eurydice_arr_9c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $4size_t
*/
प्रकार काष्ठा Eurydice_arr_68_s { Eurydice_borrow_slice_u8 तथ्य[4U]; } Eurydice_arr_68;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d46(Eurydice_arr_ec *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_5f0(Eurydice_arr_c5 *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)168U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $1size_t
*/
प्रकार काष्ठा Eurydice_arr_88_s { Eurydice_arr_c5 तथ्य[1U]; } Eurydice_arr_88;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 64
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_17(Eurydice_arr_c7 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)64U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 48
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_9f(Eurydice_arr_65 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)48U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 32
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_01(Eurydice_arr_ec *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)32U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $28size_t
*/
प्रकार काष्ठा Eurydice_arr_a2_s { uint8_t तथ्य[28U]; } Eurydice_arr_a2;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 28
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8 Eurydice_array_to_slice_mut_5e(Eurydice_arr_a2 *a)
{
  Eurydice_mut_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)28U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $104size_t
*/
प्रकार काष्ठा Eurydice_arr_c4_s { uint8_t तथ्य[104U]; } Eurydice_arr_c4;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 104
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_72(स्थिर Eurydice_arr_c4 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)104U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 104
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d45(Eurydice_arr_c4 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $144size_t
*/
प्रकार काष्ठा Eurydice_arr_f4_s { uint8_t तथ्य[144U]; } Eurydice_arr_f4;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 144
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_38(स्थिर Eurydice_arr_f4 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)144U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 144
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d44(Eurydice_arr_f4 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $72size_t
*/
प्रकार काष्ठा Eurydice_arr_ab_s { uint8_t तथ्य[72U]; } Eurydice_arr_ab;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 72
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_e2(स्थिर Eurydice_arr_ab *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)72U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 72
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d43(Eurydice_arr_ab *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.slice_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t

*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_slice_subslice_to_shared_72(Eurydice_borrow_slice_u8 s, माप_प्रकार r)
{
  वापस (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = s.ptr, .meta = r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_from_mut_5f(Eurydice_arr_ff *a, माप_प्रकार r)
{
  वापस
    (KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){ .ptr = a->तथ्य + r, .meta = (माप_प्रकार)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 8
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_subslice_to_shared_21(स्थिर Eurydice_array_u8x8 *a, माप_प्रकार r)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = r;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 8
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_6e(स्थिर Eurydice_array_u8x8 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)8U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_slice_subslice_mut_c8(Eurydice_mut_borrow_slice_u8 s, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){ .ptr = s.ptr + r.start, .meta = r.end - r.start }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 136
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_58(स्थिर Eurydice_arr_ff *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)136U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d42(Eurydice_arr_ff *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $5size_t
*/
प्रकार काष्ठा Eurydice_arr_84_s { uint64_t तथ्य[5U]; } Eurydice_arr_84;

प्रकार काष्ठा आकार_t_x2_s
{
  माप_प्रकार fst;
  माप_प्रकार snd;
}
आकार_t_x2;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $1size_t
*/
प्रकार काष्ठा Eurydice_arr_dc_s { Eurydice_borrow_slice_u8 तथ्य[1U]; } Eurydice_arr_dc;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 168
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_array_to_slice_shared_2c(स्थिर Eurydice_arr_c5 *a)
{
  Eurydice_borrow_slice_u8 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)168U;
  वापस lit;
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_array_u8x8, core_array_TryFromSliceError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_8e_s
{
  core_परिणाम_परिणाम_57_tags tag;
  जोड़ {
    Eurydice_array_u8x8 case_Ok;
    core_array_TryFromSliceError case_Err;
  }
  val;
}
core_परिणाम_परिणाम_8e;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$8size_t]], core_array_TryFromSliceError

*/
अटल अंतरभूत Eurydice_array_u8x8 core_परिणाम_unwrap_26_e0(core_परिणाम_परिणाम_8e self)
{
  अगर (self.tag == core_परिणाम_Ok)
  {
    वापस self.val.case_Ok;
  }
  अन्यथा
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d41(Eurydice_arr_c5 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $24size_t
*/
प्रकार काष्ठा Eurydice_arr_22_s { uint64_t तथ्य[24U]; } Eurydice_arr_22;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_ff
with const generics
- $1size_t
*/
प्रकार काष्ठा Eurydice_arr_0b_s { Eurydice_arr_ff तथ्य[1U]; } Eurydice_arr_0b;

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $25size_t
*/
प्रकार काष्ठा Eurydice_arr_7c_s { uint64_t तथ्य[25U]; } Eurydice_arr_7c;

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
अटल अंतरभूत Eurydice_borrow_slice_u8
Eurydice_slice_subslice_shared_c8(Eurydice_borrow_slice_u8 s, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_borrow_slice_u8){ .ptr = s.ptr + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $8size_t
*/
प्रकार काष्ठा Eurydice_arr_4d_s { int32_t तथ्य[8U]; } Eurydice_arr_4d;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 8
*/
अटल अंतरभूत Eurydice_dst_ref_shared_83
Eurydice_array_to_subslice_shared_44(स्थिर Eurydice_arr_4d *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_83){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start }
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
अटल KRML_MUSTINLINE व्योम libcrux_secrets_mem_requests_ct_declassify_5f(स्थिर bool *val)
{

}

प्रकार काष्ठा int32_t_x2_s
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
अटल अंतरभूत Eurydice_dst_ref_shared_83
Eurydice_array_to_slice_shared_fd(स्थिर Eurydice_arr_4d *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)8U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
अटल अंतरभूत Eurydice_dst_ref_shared_83
Eurydice_slice_subslice_shared_47(Eurydice_dst_ref_shared_83 s, core_ops_range_Range_87 r)
{
  वापस
    (KRML_CLITERAL(Eurydice_dst_ref_shared_83){ .ptr = s.ptr + r.start, .meta = r.end - r.start });
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types int32_t
with const generics
- N= 8
*/
अटल अंतरभूत Eurydice_dst_ref_mut_83 Eurydice_array_to_slice_mut_fd(Eurydice_arr_4d *a)
{
  Eurydice_dst_ref_mut_83 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)8U;
  वापस lit;
}

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_c9

*/
प्रकार काष्ठा core_option_Option_57_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_c9 f0;
}
core_option_Option_57;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 34
*/
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d40(Eurydice_arr_31 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

प्रकार काष्ठा uint8_t_x2_s
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
अटल अंतरभूत Eurydice_mut_borrow_slice_u8
Eurydice_array_to_subslice_mut_d4(Eurydice_arr_91 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_mut_borrow_slice_u8){
        .ptr = a->तथ्य + r.start,
        .meta = r.end - r.start
      }
    );
}

प्रकार काष्ठा libcrux_ml_kem_utils_extraction_helper_Keypair768_s
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
अटल KRML_MUSTINLINE uint64_t
libcrux_secrets_int_public_integers_declassify_d8_49(uint64_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint32_t

*/
अटल KRML_MUSTINLINE uint32_t
libcrux_secrets_int_public_integers_classify_27_df(uint32_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint64_t

*/
अटल KRML_MUSTINLINE uint64_t
libcrux_secrets_int_public_integers_classify_27_49(uint64_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint16_t

*/
अटल KRML_MUSTINLINE uint16_t
libcrux_secrets_int_public_integers_declassify_d8_de(uint16_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint16_t

*/
अटल KRML_MUSTINLINE uint16_t
libcrux_secrets_int_public_integers_classify_27_de(uint16_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint32_t

*/
अटल KRML_MUSTINLINE uint32_t
libcrux_secrets_int_public_integers_declassify_d8_df(uint32_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int32_t

*/
अटल KRML_MUSTINLINE int32_t
libcrux_secrets_int_public_integers_declassify_d8_a8(int32_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int32_t

*/
अटल KRML_MUSTINLINE int32_t libcrux_secrets_int_public_integers_classify_27_a8(int32_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint8_t

*/
अटल KRML_MUSTINLINE uint8_t
libcrux_secrets_int_public_integers_declassify_d8_90(uint8_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int16_t

*/
अटल KRML_MUSTINLINE int16_t libcrux_secrets_int_public_integers_classify_27_39(int16_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int16_t

*/
अटल KRML_MUSTINLINE int16_t
libcrux_secrets_int_public_integers_declassify_d8_39(int16_t self)
{
  वापस self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint8_t

*/
अटल KRML_MUSTINLINE uint8_t libcrux_secrets_int_public_integers_classify_27_90(uint8_t self)
{
  वापस self;
}

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा combined_core_H_DEFINED
#पूर्ण_अगर /* combined_core_H */

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


#अगर_अघोषित libcrux_sha3_portable_H
#घोषणा libcrux_sha3_portable_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


/**
A monomorphic instance of libcrux_sha3.generic_keccak.KeccakState
with types uint64_t
with const generics
- $1size_t
*/
प्रकार Eurydice_arr_7c libcrux_sha3_generic_keccak_KeccakState_f3;

प्रकार libcrux_sha3_generic_keccak_KeccakState_f3 libcrux_sha3_portable_KeccakState;

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $136size_t
*/
प्रकार काष्ठा libcrux_sha3_generic_keccak_xof_KeccakXofState_8d_s
{
  Eurydice_arr_7c inner;
  Eurydice_arr_0b buf;
  माप_प्रकार buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_8d;

प्रकार libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_portable_incremental_Shake256Xof;

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_zero_d2(व्योम)
{
  वापस 0ULL;
}

अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__veor5q_u64(
  uint64_t a,
  uint64_t b,
  uint64_t c,
  uint64_t d,
  uint64_t e
)
{
  वापस (((a ^ b) ^ c) ^ d) ^ e;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor5_d2(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
  वापस libcrux_sha3_simd_portable__veor5q_u64(a, b, c, d, e);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 1
- RIGHT= 63
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_76(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)1);
}

अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__vrax1q_u64(uint64_t a, uint64_t b)
{
  वापस a ^ libcrux_sha3_simd_portable_rotate_बायाँ_76(b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vrax1q_u64(a, b);
}

अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vbcaxq_u64(uint64_t a, uint64_t b, uint64_t c)
{
  वापस a ^ (b & ~c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_and_not_xor_d2(uint64_t a, uint64_t b, uint64_t c)
{
  वापस libcrux_sha3_simd_portable__vbcaxq_u64(a, b, c);
}

अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__veorq_n_u64(uint64_t a, uint64_t c)
{
  वापस a ^ c;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_constant_d2(uint64_t a, uint64_t c)
{
  वापस libcrux_sha3_simd_portable__veorq_n_u64(a, c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_xor_d2(uint64_t a, uint64_t b)
{
  वापस a ^ b;
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
अटल KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_generic_keccak_new_80_71(व्योम)
{
  Eurydice_arr_7c lit;
  uint64_t repeat_expression[25U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)25U; i++)
  {
    repeat_expression[i] = libcrux_sha3_simd_portable_zero_d2();
  }
  स_नकल(lit.तथ्य, repeat_expression, (माप_प्रकार)25U * माप (uint64_t));
  वापस lit;
}

/**
 Create a new SHAKE-128 state object.
*/
अटल KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_portable_incremental_shake128_init(व्योम)
{
  वापस libcrux_sha3_generic_keccak_new_80_71();
}

#घोषणा LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS ((KRML_CLITERAL(Eurydice_arr_22){ .तथ्य = { 1ULL, 32898ULL, 9223372036854808714ULL, 9223372039002292224ULL, 32907ULL, 2147483649ULL, 9223372039002292353ULL, 9223372036854808585ULL, 138ULL, 136ULL, 2147516425ULL, 2147483658ULL, 2147516555ULL, 9223372036854775947ULL, 9223372036854808713ULL, 9223372036854808579ULL, 9223372036854808578ULL, 9223372036854775936ULL, 32778ULL, 9223372039002259466ULL, 9223372039002292353ULL, 9223372036854808704ULL, 2147483649ULL, 9223372039002292232ULL } }))

/**
A monomorphic instance of libcrux_sha3.traits.get_ij
with types uint64_t
with const generics
- N= 1
*/
अटल KRML_MUSTINLINE स्थिर
uint64_t
*libcrux_sha3_traits_get_ij_71(स्थिर Eurydice_arr_7c *arr, माप_प्रकार i, माप_प्रकार j)
{
  वापस &arr->तथ्य[(माप_प्रकार)5U * j + i];
}

/**
A monomorphic instance of libcrux_sha3.traits.set_ij
with types uint64_t
with const generics
- N= 1
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_traits_set_ij_71(Eurydice_arr_7c *arr, माप_प्रकार i, माप_प्रकार j, uint64_t मूल्य)
{
  arr->तथ्य[(माप_प्रकार)5U * j + i] = मूल्य;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 168
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_block_60(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start
)
{
  Eurydice_arr_7c state_flat = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)168U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार offset = start + (माप_प्रकार)8U * i0;
    Eurydice_array_u8x8 arr;
    स_नकल(arr.तथ्य,
      Eurydice_slice_subslice_shared_c8(blocks,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = offset, .end = offset + (माप_प्रकार)8U })).ptr,
      (माप_प्रकार)8U * माप (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_परिणाम_unwrap_26_e0((
          KRML_CLITERAL(core_परिणाम_परिणाम_8e){ .tag = core_परिणाम_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.तथ्य[i0] = core_अंक_u64_from_le_bytes(uu____0);
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)168U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_sha3_traits_set_ij_71(state,
      i0 / (माप_प्रकार)5U,
      i0 % (माप_प्रकार)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (माप_प्रकार)5U, i0 % (माप_प्रकार)5U)[0U] ^
        state_flat.तथ्य[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 168
- DELIMITER= 31
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_last_37(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  Eurydice_arr_c5 बफर = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d41(&बफर,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = len })),
    Eurydice_slice_subslice_shared_c8(blocks,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = start, .end = start + len })),
    uint8_t);
  बफर.तथ्य[len] = 31U;
  माप_प्रकार uu____0 = (माप_प्रकार)168U - (माप_प्रकार)1U;
  बफर.तथ्य[uu____0] = (uint32_t)बफर.तथ्य[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_60(state,
    Eurydice_array_to_slice_shared_2c(&बफर),
    (माप_प्रकार)0U);
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_last_a1_37(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_37(self, निवेश->तथ्य[0U], start, len);
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
अटल अंतरभूत स्थिर
uint64_t
*libcrux_sha3_generic_keccak_सूचकांक_c2_71(स्थिर Eurydice_arr_7c *self, आकार_t_x2 index)
{
  वापस libcrux_sha3_traits_get_ij_71(self, index.fst, index.snd);
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
अटल KRML_MUSTINLINE Eurydice_arr_84
libcrux_sha3_generic_keccak_theta_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_84
  c =
    {
      .तथ्य = {
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)0U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)0U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)0U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)0U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)0U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)1U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)1U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)1U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)1U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)1U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)2U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)2U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)2U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)2U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)2U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)3U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)3U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)3U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)3U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)3U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)4U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)4U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)4U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)4U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)4U }))[0U])
      }
    };
  वापस
    (
      KRML_CLITERAL(Eurydice_arr_84){
        .तथ्य = {
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.तथ्य[((माप_प्रकार)0U + (माप_प्रकार)4U) %
              (माप_प्रकार)5U],
            c.तथ्य[((माप_प्रकार)0U + (माप_प्रकार)1U) % (माप_प्रकार)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.तथ्य[((माप_प्रकार)1U + (माप_प्रकार)4U) %
              (माप_प्रकार)5U],
            c.तथ्य[((माप_प्रकार)1U + (माप_प्रकार)1U) % (माप_प्रकार)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.तथ्य[((माप_प्रकार)2U + (माप_प्रकार)4U) %
              (माप_प्रकार)5U],
            c.तथ्य[((माप_प्रकार)2U + (माप_प्रकार)1U) % (माप_प्रकार)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.तथ्य[((माप_प्रकार)3U + (माप_प्रकार)4U) %
              (माप_प्रकार)5U],
            c.तथ्य[((माप_प्रकार)3U + (माप_प्रकार)1U) % (माप_प्रकार)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.तथ्य[((माप_प्रकार)4U + (माप_प्रकार)4U) %
              (माप_प्रकार)5U],
            c.तथ्य[((माप_प्रकार)4U + (माप_प्रकार)1U) % (माप_प्रकार)5U])
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
अटल अंतरभूत व्योम
libcrux_sha3_generic_keccak_set_80_71(Eurydice_arr_7c *self, माप_प्रकार i, माप_प्रकार j, uint64_t v)
{
  libcrux_sha3_traits_set_ij_71(self, i, j, v);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 36
- RIGHT= 28
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_02(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)36);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 36
- RIGHT= 28
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_02(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_02(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_02(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_02(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 3
- RIGHT= 61
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_ac(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)3);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 3
- RIGHT= 61
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ac(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_ac(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_ac(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 41
- RIGHT= 23
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_020(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)41);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 41
- RIGHT= 23
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_020(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_020(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_020(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_020(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 18
- RIGHT= 46
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_a9(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)18);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 18
- RIGHT= 46
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_a9(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_a9(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_a9(a, b);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_rho_0_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)0U,
    libcrux_sha3_simd_portable_xor_d2(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)0U }))[0U],
      t.तथ्य[0U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_02(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)0U }))[0U],
      t.तथ्य[0U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)0U }))[0U],
      t.तथ्य[0U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_020(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)0U }))[0U],
      t.तथ्य[0U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)0U }))[0U],
      t.तथ्य[0U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 1
- RIGHT= 63
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_76(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_76(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_76(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_76(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 44
- RIGHT= 20
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_58(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)44);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 44
- RIGHT= 20
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_58(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_58(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_58(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_58(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 10
- RIGHT= 54
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_e0(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)10);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 10
- RIGHT= 54
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_e0(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_e0(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_e0(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 45
- RIGHT= 19
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_63(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)45);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 45
- RIGHT= 19
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_63(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_63(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_63(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_63(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 2
- RIGHT= 62
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_6a(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)2);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 2
- RIGHT= 62
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6a(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_6a(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_6a(a, b);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_rho_1_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_76(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)1U }))[0U],
      t.तथ्य[1U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_58(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)1U }))[0U],
      t.तथ्य[1U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)1U }))[0U],
      t.तथ्य[1U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_63(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)1U }))[0U],
      t.तथ्य[1U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)1U }))[0U],
      t.तथ्य[1U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 62
- RIGHT= 2
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_ab(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)62);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 62
- RIGHT= 2
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ab(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_ab(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_ab(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 6
- RIGHT= 58
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_5b(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)6);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 6
- RIGHT= 58
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_5b(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_5b(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_5b(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 43
- RIGHT= 21
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_6f(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)43);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 43
- RIGHT= 21
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6f(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_6f(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_6f(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 15
- RIGHT= 49
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_62(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)15);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 15
- RIGHT= 49
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_62(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_62(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_62(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_62(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 61
- RIGHT= 3
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_23(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)61);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 61
- RIGHT= 3
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_23(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_23(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_23(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_23(a, b);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_rho_2_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)2U }))[0U],
      t.तथ्य[2U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)2U }))[0U],
      t.तथ्य[2U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)2U }))[0U],
      t.तथ्य[2U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_62(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)2U }))[0U],
      t.तथ्य[2U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_23(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)2U }))[0U],
      t.तथ्य[2U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 28
- RIGHT= 36
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_37(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)28);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 28
- RIGHT= 36
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_37(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_37(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_37(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_37(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 55
- RIGHT= 9
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_bb(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)55);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 55
- RIGHT= 9
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_bb(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_bb(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_bb(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 25
- RIGHT= 39
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_b9(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)25);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 25
- RIGHT= 39
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_b9(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_b9(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_b9(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 21
- RIGHT= 43
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_54(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)21);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 21
- RIGHT= 43
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_54(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_54(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_54(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_54(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 56
- RIGHT= 8
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_4c(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)56);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 56
- RIGHT= 8
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_4c(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_4c(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_4c(a, b);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_rho_3_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_37(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)3U }))[0U],
      t.तथ्य[3U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)3U }))[0U],
      t.तथ्य[3U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)3U }))[0U],
      t.तथ्य[3U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_54(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)3U }))[0U],
      t.तथ्य[3U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)3U }))[0U],
      t.तथ्य[3U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 27
- RIGHT= 37
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_ce(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)27);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 27
- RIGHT= 37
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ce(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_ce(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_ce(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 20
- RIGHT= 44
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_77(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)20);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 20
- RIGHT= 44
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_77(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_77(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_77(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_77(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 39
- RIGHT= 25
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_25(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)39);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 39
- RIGHT= 25
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_25(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_25(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_25(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_25(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 8
- RIGHT= 56
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_af(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)8);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 8
- RIGHT= 56
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_af(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_af(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_af(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_af(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 14
- RIGHT= 50
*/
अटल KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_बायाँ_fd(uint64_t x)
{
  वापस core_अंक_u64_rotate_बायाँ(x, (uint32_t)14);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 14
- RIGHT= 50
*/
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_fd(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable_rotate_बायाँ_fd(a ^ b);
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
अटल KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(uint64_t a, uint64_t b)
{
  वापस libcrux_sha3_simd_portable__vxarq_u64_fd(a, b);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_rho_4_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)4U }))[0U],
      t.तथ्य[4U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_77(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)4U }))[0U],
      t.तथ्य[4U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_25(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)4U }))[0U],
      t.तथ्य[4U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_af(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)4U }))[0U],
      t.तथ्य[4U]));
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)4U }))[0U],
      t.तथ्य[4U]));
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
अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_pi_0_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)0U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)3U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)0U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)1U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)0U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)4U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)0U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)2U }))[0U]);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_pi_1_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)1U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)1U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)1U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)4U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)1U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)2U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)1U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)0U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)1U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)1U, .snd = (माप_प्रकार)3U }))[0U]);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_pi_2_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)2U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)2U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)2U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)0U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)2U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)3U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)2U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)1U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)2U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)2U, .snd = (माप_प्रकार)4U }))[0U]);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_pi_3_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)3U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)3U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)3U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)1U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)3U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)4U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)3U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)2U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)3U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)3U, .snd = (माप_प्रकार)0U }))[0U]);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_pi_4_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)4U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)4U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)1U,
    (माप_प्रकार)4U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)2U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)2U,
    (माप_प्रकार)4U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)0U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)3U,
    (माप_प्रकार)4U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)3U }))[0U]);
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)4U,
    (माप_प्रकार)4U,
    libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
      (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)4U, .snd = (माप_प्रकार)1U }))[0U]);
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
अटल KRML_MUSTINLINE व्योम libcrux_sha3_generic_keccak_pi_80_71(Eurydice_arr_7c *self)
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
अटल KRML_MUSTINLINE व्योम libcrux_sha3_generic_keccak_chi_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_7c old = self[0U];
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < (माप_प्रकार)5U; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)5U; i++)
    {
      माप_प्रकार j = i;
      libcrux_sha3_generic_keccak_set_80_71(self,
        i1,
        j,
        libcrux_sha3_simd_portable_and_not_xor_d2(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
            (KRML_CLITERAL(आकार_t_x2){ .fst = i1, .snd = j }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
            (KRML_CLITERAL(आकार_t_x2){ .fst = i1, .snd = (j + (माप_प्रकार)2U) % (माप_प्रकार)5U }))[0U],
          libcrux_sha3_generic_keccak_सूचकांक_c2_71(&old,
            (KRML_CLITERAL(आकार_t_x2){ .fst = i1, .snd = (j + (माप_प्रकार)1U) % (माप_प्रकार)5U }))[0U]));
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_iota_80_71(Eurydice_arr_7c *self, माप_प्रकार i)
{
  libcrux_sha3_generic_keccak_set_80_71(self,
    (माप_प्रकार)0U,
    (माप_प्रकार)0U,
    libcrux_sha3_simd_portable_xor_constant_d2(libcrux_sha3_generic_keccak_सूचकांक_c2_71(self,
        (KRML_CLITERAL(आकार_t_x2){ .fst = (माप_प्रकार)0U, .snd = (माप_प्रकार)0U }))[0U],
      LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS.तथ्य[i]));
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_keccakf1600_80_71(Eurydice_arr_7c *self)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)24U; i++)
  {
    माप_प्रकार i0 = i;
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_final_80_bd(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_a1_37(self, निवेश, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
 Absorb
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_incremental_shake128_absorb_final(
  Eurydice_arr_7c *s,
  Eurydice_borrow_slice_u8 data0
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { data0 } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd(s, &lvalue, (माप_प्रकार)0U, data0.meta);
}

/**
 Create a new SHAKE-256 state object.
*/
अटल KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_portable_incremental_shake256_init(व्योम)
{
  वापस libcrux_sha3_generic_keccak_new_80_71();
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 136
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_block_b2(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start
)
{
  Eurydice_arr_7c state_flat = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)136U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार offset = start + (माप_प्रकार)8U * i0;
    Eurydice_array_u8x8 arr;
    स_नकल(arr.तथ्य,
      Eurydice_slice_subslice_shared_c8(blocks,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = offset, .end = offset + (माप_प्रकार)8U })).ptr,
      (माप_प्रकार)8U * माप (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_परिणाम_unwrap_26_e0((
          KRML_CLITERAL(core_परिणाम_परिणाम_8e){ .tag = core_परिणाम_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.तथ्य[i0] = core_अंक_u64_from_le_bytes(uu____0);
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)136U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_sha3_traits_set_ij_71(state,
      i0 / (माप_प्रकार)5U,
      i0 % (माप_प्रकार)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (माप_प्रकार)5U, i0 % (माप_प्रकार)5U)[0U] ^
        state_flat.तथ्य[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 31
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_last_22(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  Eurydice_arr_ff बफर = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d42(&बफर,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = len })),
    Eurydice_slice_subslice_shared_c8(blocks,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = start, .end = start + len })),
    uint8_t);
  बफर.तथ्य[len] = 31U;
  माप_प्रकार uu____0 = (माप_प्रकार)136U - (माप_प्रकार)1U;
  बफर.तथ्य[uu____0] = (uint32_t)बफर.तथ्य[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_b2(state,
    Eurydice_array_to_slice_shared_58(&बफर),
    (माप_प्रकार)0U);
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_last_a1_22(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_22(self, निवेश->तथ्य[0U], start, len);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_final_80_bd0(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_a1_22(self, निवेश, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
 Absorb some data for SHAKE-256 for the last time
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_incremental_shake256_absorb_final(
  Eurydice_arr_7c *s,
  Eurydice_borrow_slice_u8 तथ्य
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { तथ्य } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd0(s, &lvalue, (माप_प्रकार)0U, तथ्य.meta);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 168
*/
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_block_a1_60(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_60(self, निवेश->तथ्य[0U], start);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_block_80_e9(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_a1_60(self, निवेश, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 168
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_store_block_60(
  स्थिर Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  माप_प्रकार octets = len / (माप_प्रकार)8U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < octets; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          i0 / (माप_प्रकार)5U,
          i0 % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + (माप_प्रकार)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + (माप_प्रकार)8U })),
      Eurydice_array_to_slice_shared_6e(&bytes),
      uint8_t);
  }
  माप_प्रकार remaining = len % (माप_प्रकार)8U;
  अगर (remaining > (माप_प्रकार)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          octets / (माप_प्रकार)5U,
          octets % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_21(&bytes, remaining),
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_squeeze_9b_60(
  स्थिर Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_store_block_60(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 168
- DELIM= 31
*/
अटल अंतरभूत व्योम
libcrux_sha3_generic_keccak_portable_keccak1_37(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  माप_प्रकार निवेश_len = निवेश.meta;
  माप_प्रकार निवेश_blocks = निवेश_len / (माप_प्रकार)168U;
  माप_प्रकार निवेश_rem = निवेश_len % (माप_प्रकार)168U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < निवेश_blocks; i++)
  {
    माप_प्रकार i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
    libcrux_sha3_generic_keccak_absorb_block_80_e9(&s, &lvalue, i0 * (माप_प्रकार)168U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd(&s, &lvalue, निवेश_len - निवेश_rem, निवेश_rem);
  माप_प्रकार output_len = output.meta;
  माप_प्रकार output_blocks = output_len / (माप_प्रकार)168U;
  माप_प्रकार output_rem = output_len % (माप_प्रकार)168U;
  अगर (output_blocks == (माप_प्रकार)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, (माप_प्रकार)0U, output_len);
  }
  अन्यथा
  {
    libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, (माप_प्रकार)0U, (माप_प्रकार)168U);
    क्रम (माप_प्रकार i = (माप_प्रकार)1U; i < output_blocks; i++)
    {
      माप_प्रकार i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, i0 * (माप_प्रकार)168U, (माप_प्रकार)168U);
    }
    अगर (output_rem != (माप_प्रकार)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE128 implementation.
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_shake128(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 तथ्य
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_37(तथ्य, digest);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 136
*/
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_block_a1_b2(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_b2(self, निवेश->तथ्य[0U], start);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_block_80_e90(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_a1_b2(self, निवेश, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 136
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_store_block_b2(
  स्थिर Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  माप_प्रकार octets = len / (माप_प्रकार)8U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < octets; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          i0 / (माप_प्रकार)5U,
          i0 % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + (माप_प्रकार)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + (माप_प्रकार)8U })),
      Eurydice_array_to_slice_shared_6e(&bytes),
      uint8_t);
  }
  माप_प्रकार remaining = len % (माप_प्रकार)8U;
  अगर (remaining > (माप_प्रकार)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          octets / (माप_प्रकार)5U,
          octets % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_21(&bytes, remaining),
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_squeeze_9b_b2(
  स्थिर Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_store_block_b2(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 31
*/
अटल अंतरभूत व्योम
libcrux_sha3_generic_keccak_portable_keccak1_22(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  माप_प्रकार निवेश_len = निवेश.meta;
  माप_प्रकार निवेश_blocks = निवेश_len / (माप_प्रकार)136U;
  माप_प्रकार निवेश_rem = निवेश_len % (माप_प्रकार)136U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < निवेश_blocks; i++)
  {
    माप_प्रकार i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
    libcrux_sha3_generic_keccak_absorb_block_80_e90(&s, &lvalue, i0 * (माप_प्रकार)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd0(&s, &lvalue, निवेश_len - निवेश_rem, निवेश_rem);
  माप_प्रकार output_len = output.meta;
  माप_प्रकार output_blocks = output_len / (माप_प्रकार)136U;
  माप_प्रकार output_rem = output_len % (माप_प्रकार)136U;
  अगर (output_blocks == (माप_प्रकार)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (माप_प्रकार)0U, output_len);
  }
  अन्यथा
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (माप_प्रकार)0U, (माप_प्रकार)136U);
    क्रम (माप_प्रकार i = (माप_प्रकार)1U; i < output_blocks; i++)
    {
      माप_प्रकार i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, i0 * (माप_प्रकार)136U, (माप_प्रकार)136U);
    }
    अगर (output_rem != (माप_प्रकार)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE256 implementation.
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_shake256(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 तथ्य
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_22(तथ्य, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_block_b4
with const generics
- RATE= 136
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_portable_squeeze_first_block_b4_b2(
  स्थिर Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_simd_portable_squeeze_9b_b2(self, out, (माप_प्रकार)0U, (माप_प्रकार)136U);
}

/**
 Squeeze the first SHAKE-256 block
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_incremental_shake256_squeeze_first_block(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_first_block_b4_b2(&s[0U], out);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_five_blocks_b4
with const generics
- RATE= 168
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_portable_squeeze_first_five_blocks_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_simd_portable_squeeze_9b_60(self, out, (माप_प्रकार)0U, (माप_प्रकार)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, out, (माप_प्रकार)168U, (माप_प्रकार)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, out, (माप_प्रकार)2U * (माप_प्रकार)168U, (माप_प्रकार)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, out, (माप_प्रकार)3U * (माप_प्रकार)168U, (माप_प्रकार)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, out, (माप_प्रकार)4U * (माप_प्रकार)168U, (माप_प्रकार)168U);
}

/**
 Squeeze five blocks
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_first_five_blocks_b4_60(s, out0);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 168
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_portable_squeeze_अग्र_block_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, out, start, (माप_प्रकार)168U);
}

/**
 Squeeze another block
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_incremental_shake128_squeeze_अग्र_block(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_अग्र_block_b4_60(s, out0, (माप_प्रकार)0U);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 136
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_portable_squeeze_अग्र_block_b4_b2(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_b2(self, out, start, (माप_प्रकार)136U);
}

/**
 Squeeze the next SHAKE-256 block
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_incremental_shake256_squeeze_अग्र_block(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_अग्र_block_b4_b2(s, out, (माप_प्रकार)0U);
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
अटल अंतरभूत माप_प्रकार
libcrux_sha3_generic_keccak_xof_fill_बफर_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  स्थिर Eurydice_arr_dc *inputs
)
{
  माप_प्रकार निवेश_len = inputs->तथ्य->meta;
  माप_प्रकार uu____0;
  अगर (self->buf_len != (माप_प्रकार)0U)
  {
    अगर (निवेश_len >= (माप_प्रकार)136U - self->buf_len)
    {
      माप_प्रकार consumed = (माप_प्रकार)136U - self->buf_len;
      क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)1U; i++)
      {
        माप_प्रकार i0 = i;
        Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_5f(&self->buf.तथ्य[i0],
            self->buf_len),
          Eurydice_slice_subslice_to_shared_72(inputs->तथ्य[i0], consumed),
          uint8_t);
      }
      self->buf_len = (माप_प्रकार)136U;
      uu____0 = consumed;
    }
    अन्यथा
    {
      uu____0 = (माप_प्रकार)0U;
    }
  }
  अन्यथा
  {
    uu____0 = (माप_प्रकार)0U;
  }
  वापस uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $136size_t
*/
प्रकार स्थिर Eurydice_arr_0b *libcrux_sha3_generic_keccak_xof_buf_to_slices_closure_94;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_2a
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_2a_81(
  स्थिर Eurydice_arr_0b **_,
  माप_प्रकार tupled_args
)
{
  माप_प्रकार i = tupled_args;
  वापस
    core_array___T__N___as_slice((माप_प्रकार)136U,
      &_[0U]->तथ्य[i],
      uint8_t,
      Eurydice_borrow_slice_u8);
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
अटल अंतरभूत Eurydice_borrow_slice_u8
libcrux_sha3_generic_keccak_xof_buf_to_slices_call_once_fa_81(
  स्थिर Eurydice_arr_0b *_,
  माप_प्रकार _0
)
{
  वापस libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_2a_81(&_, _0);
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
अटल KRML_MUSTINLINE Eurydice_arr_dc
libcrux_sha3_generic_keccak_xof_buf_to_slices_81(स्थिर Eurydice_arr_0b *buf)
{
  Eurydice_arr_dc arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)1U; i++)
  {
    arr_struct.तथ्य[i] = libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_2a_81(&buf, i);
  }
  वापस arr_struct;
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
अटल अंतरभूत माप_प्रकार
libcrux_sha3_generic_keccak_xof_absorb_full_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  स्थिर Eurydice_arr_dc *inputs
)
{
  माप_प्रकार consumed = libcrux_sha3_generic_keccak_xof_fill_बफर_35_e9(self, inputs);
  अगर (self->buf_len == (माप_प्रकार)136U)
  {
    Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_to_slices_81(&self->buf);
    libcrux_sha3_simd_portable_load_block_a1_b2(&self->inner, &borrowed, (माप_प्रकार)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    self->buf_len = (माप_प्रकार)0U;
  }
  माप_प्रकार निवेश_to_consume = inputs->तथ्य->meta - consumed;
  माप_प्रकार अंक_blocks = निवेश_to_consume / (माप_प्रकार)136U;
  माप_प्रकार remainder = निवेश_to_consume % (माप_प्रकार)136U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < अंक_blocks; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार start = i0 * (माप_प्रकार)136U + consumed;
    libcrux_sha3_simd_portable_load_block_a1_b2(&self->inner, inputs, start);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
  }
  वापस remainder;
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_xof_absorb_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  स्थिर Eurydice_arr_dc *inputs
)
{
  माप_प्रकार remainder = libcrux_sha3_generic_keccak_xof_absorb_full_35_e9(self, inputs);
  अगर (remainder > (माप_प्रकार)0U)
  {
    माप_प्रकार निवेश_len = inputs->तथ्य->meta;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)1U; i++)
    {
      माप_प्रकार i0 = i;
      Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d42(&self->buf.तथ्य[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .start = self->buf_len,
              .end = self->buf_len + remainder
            }
          )),
        Eurydice_slice_subslice_shared_c8(inputs->तथ्य[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .start = निवेश_len - remainder,
              .end = निवेश_len
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
अटल अंतरभूत व्योम
libcrux_sha3_portable_incremental_absorb_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_slice_u8 निवेश
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_xof_absorb_final_35_bd(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  स्थिर Eurydice_arr_dc *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_e9(self, inputs);
  Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_to_slices_81(&self->buf);
  libcrux_sha3_simd_portable_load_last_a1_22(&self->inner, &borrowed, (माप_प्रकार)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
}

/**
 Shake256 absorb final
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
अटल अंतरभूत व्योम
libcrux_sha3_portable_incremental_absorb_final_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_slice_u8 निवेश
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
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
अटल अंतरभूत Eurydice_arr_ff libcrux_sha3_generic_keccak_xof_zero_block_35_e9(व्योम)
{
  वापस (KRML_CLITERAL(Eurydice_arr_ff){ .तथ्य = { 0U } });
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
अटल अंतरभूत libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_generic_keccak_xof_new_35_e9(व्योम)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_71();
  Eurydice_arr_ff repeat_expression[1U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)1U; i++)
  {
    repeat_expression[i] = libcrux_sha3_generic_keccak_xof_zero_block_35_e9();
  }
  स_नकल(lit.buf.तथ्य, repeat_expression, (माप_प्रकार)1U * माप (Eurydice_arr_ff));
  lit.buf_len = (माप_प्रकार)0U;
  lit.sponge = false;
  वापस lit;
}

/**
 Shake256 new state
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
अटल अंतरभूत libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_portable_incremental_new_42(व्योम)
{
  वापस libcrux_sha3_generic_keccak_xof_new_35_e9();
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_xof_squeeze_85_76(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  माप_प्रकार out_len = out.meta;
  अगर (!(out_len == (माप_प्रकार)0U))
  {
    अगर (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    }
    अगर (out_len > (माप_प्रकार)0U)
    {
      माप_प्रकार blocks = out_len / (माप_प्रकार)136U;
      माप_प्रकार last = out_len - out_len % (माप_प्रकार)136U;
      अगर (blocks == (माप_प्रकार)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, out, (माप_प्रकार)0U, out_len);
      }
      अन्यथा
      {
        libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, out, (माप_प्रकार)0U, (माप_प्रकार)136U);
        क्रम (माप_प्रकार i = (माप_प्रकार)1U; i < blocks; i++)
        {
          माप_प्रकार i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner,
            out,
            i0 * (माप_प्रकार)136U,
            (माप_प्रकार)136U);
        }
        अगर (last < out_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, out, last, out_len - last);
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
अटल अंतरभूत व्योम
libcrux_sha3_portable_incremental_squeeze_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_76(self, out);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 72
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_block_c6(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start
)
{
  Eurydice_arr_7c state_flat = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)72U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार offset = start + (माप_प्रकार)8U * i0;
    Eurydice_array_u8x8 arr;
    स_नकल(arr.तथ्य,
      Eurydice_slice_subslice_shared_c8(blocks,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = offset, .end = offset + (माप_प्रकार)8U })).ptr,
      (माप_प्रकार)8U * माप (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_परिणाम_unwrap_26_e0((
          KRML_CLITERAL(core_परिणाम_परिणाम_8e){ .tag = core_परिणाम_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.तथ्य[i0] = core_अंक_u64_from_le_bytes(uu____0);
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)72U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_sha3_traits_set_ij_71(state,
      i0 / (माप_प्रकार)5U,
      i0 % (माप_प्रकार)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (माप_प्रकार)5U, i0 % (माप_प्रकार)5U)[0U] ^
        state_flat.तथ्य[i0]);
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_block_a1_c6(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_c6(self, निवेश->तथ्य[0U], start);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_block_80_e91(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_a1_c6(self, निवेश, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 72
- DELIMITER= 6
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_last_dc(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  Eurydice_arr_ab बफर = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d43(&बफर,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = len })),
    Eurydice_slice_subslice_shared_c8(blocks,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = start, .end = start + len })),
    uint8_t);
  बफर.तथ्य[len] = 6U;
  माप_प्रकार uu____0 = (माप_प्रकार)72U - (माप_प्रकार)1U;
  बफर.तथ्य[uu____0] = (uint32_t)बफर.तथ्य[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_c6(state,
    Eurydice_array_to_slice_shared_e2(&बफर),
    (माप_प्रकार)0U);
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_last_a1_dc(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_dc(self, निवेश->तथ्य[0U], start, len);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_final_80_bd1(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_a1_dc(self, निवेश, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 72
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_store_block_c6(
  स्थिर Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  माप_प्रकार octets = len / (माप_प्रकार)8U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < octets; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          i0 / (माप_प्रकार)5U,
          i0 % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + (माप_प्रकार)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + (माप_प्रकार)8U })),
      Eurydice_array_to_slice_shared_6e(&bytes),
      uint8_t);
  }
  माप_प्रकार remaining = len % (माप_प्रकार)8U;
  अगर (remaining > (माप_प्रकार)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          octets / (माप_प्रकार)5U,
          octets % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_21(&bytes, remaining),
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_squeeze_9b_c6(
  स्थिर Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_store_block_c6(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 72
- DELIM= 6
*/
अटल अंतरभूत व्योम
libcrux_sha3_generic_keccak_portable_keccak1_dc(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  माप_प्रकार निवेश_len = निवेश.meta;
  माप_प्रकार निवेश_blocks = निवेश_len / (माप_प्रकार)72U;
  माप_प्रकार निवेश_rem = निवेश_len % (माप_प्रकार)72U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < निवेश_blocks; i++)
  {
    माप_प्रकार i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
    libcrux_sha3_generic_keccak_absorb_block_80_e91(&s, &lvalue, i0 * (माप_प्रकार)72U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd1(&s, &lvalue, निवेश_len - निवेश_rem, निवेश_rem);
  माप_प्रकार output_len = output.meta;
  माप_प्रकार output_blocks = output_len / (माप_प्रकार)72U;
  माप_प्रकार output_rem = output_len % (माप_प्रकार)72U;
  अगर (output_blocks == (माप_प्रकार)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, (माप_प्रकार)0U, output_len);
  }
  अन्यथा
  {
    libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, (माप_प्रकार)0U, (माप_प्रकार)72U);
    क्रम (माप_प्रकार i = (माप_प्रकार)1U; i < output_blocks; i++)
    {
      माप_प्रकार i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, i0 * (माप_प्रकार)72U, (माप_प्रकार)72U);
    }
    अगर (output_rem != (माप_प्रकार)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 512 implementation.
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_sha512(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 तथ्य
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_dc(तथ्य, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 6
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_last_220(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  Eurydice_arr_ff बफर = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d42(&बफर,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = len })),
    Eurydice_slice_subslice_shared_c8(blocks,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = start, .end = start + len })),
    uint8_t);
  बफर.तथ्य[len] = 6U;
  माप_प्रकार uu____0 = (माप_प्रकार)136U - (माप_प्रकार)1U;
  बफर.तथ्य[uu____0] = (uint32_t)बफर.तथ्य[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_b2(state,
    Eurydice_array_to_slice_shared_58(&बफर),
    (माप_प्रकार)0U);
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_last_a1_220(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_220(self, निवेश->तथ्य[0U], start, len);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_final_80_bd2(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_a1_220(self, निवेश, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 6
*/
अटल अंतरभूत व्योम
libcrux_sha3_generic_keccak_portable_keccak1_220(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  माप_प्रकार निवेश_len = निवेश.meta;
  माप_प्रकार निवेश_blocks = निवेश_len / (माप_प्रकार)136U;
  माप_प्रकार निवेश_rem = निवेश_len % (माप_प्रकार)136U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < निवेश_blocks; i++)
  {
    माप_प्रकार i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
    libcrux_sha3_generic_keccak_absorb_block_80_e90(&s, &lvalue, i0 * (माप_प्रकार)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd2(&s, &lvalue, निवेश_len - निवेश_rem, निवेश_rem);
  माप_प्रकार output_len = output.meta;
  माप_प्रकार output_blocks = output_len / (माप_प्रकार)136U;
  माप_प्रकार output_rem = output_len % (माप_प्रकार)136U;
  अगर (output_blocks == (माप_प्रकार)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (माप_प्रकार)0U, output_len);
  }
  अन्यथा
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (माप_प्रकार)0U, (माप_प्रकार)136U);
    क्रम (माप_प्रकार i = (माप_प्रकार)1U; i < output_blocks; i++)
    {
      माप_प्रकार i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, i0 * (माप_प्रकार)136U, (माप_प्रकार)136U);
    }
    अगर (output_rem != (माप_प्रकार)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 256 implementation.
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_sha256(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 तथ्य
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_220(तथ्य, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_three_blocks_b4
with const generics
- RATE= 168
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_portable_squeeze_first_three_blocks_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_simd_portable_squeeze_9b_60(self, out, (माप_प्रकार)0U, (माप_प्रकार)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, out, (माप_प्रकार)168U, (माप_प्रकार)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, out, (माप_प्रकार)2U * (माप_प्रकार)168U, (माप_प्रकार)168U);
}

/**
 Squeeze three blocks
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_incremental_shake128_squeeze_first_three_blocks(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_first_three_blocks_b4_60(s, out0);
}

#घोषणा libcrux_sha3_Algorithm_Sha224 1
#घोषणा libcrux_sha3_Algorithm_Sha256 2
#घोषणा libcrux_sha3_Algorithm_Sha384 3
#घोषणा libcrux_sha3_Algorithm_Sha512 4

प्रकार uint8_t libcrux_sha3_Algorithm;

#घोषणा LIBCRUX_SHA3_SHA3_224_DIGEST_आकार ((माप_प्रकार)28U)

#घोषणा LIBCRUX_SHA3_SHA3_256_DIGEST_आकार ((माप_प्रकार)32U)

#घोषणा LIBCRUX_SHA3_SHA3_384_DIGEST_आकार ((माप_प्रकार)48U)

#घोषणा LIBCRUX_SHA3_SHA3_512_DIGEST_आकार ((माप_प्रकार)64U)

/**
 Returns the output size of a digest.
*/
अटल अंतरभूत माप_प्रकार libcrux_sha3_digest_आकार(libcrux_sha3_Algorithm mode)
{
  चयन (mode)
  {
    हाल libcrux_sha3_Algorithm_Sha224:
      {
        अवरोध;
      }
    हाल libcrux_sha3_Algorithm_Sha256:
      {
        वापस LIBCRUX_SHA3_SHA3_256_DIGEST_आकार;
      }
    हाल libcrux_sha3_Algorithm_Sha384:
      {
        वापस LIBCRUX_SHA3_SHA3_384_DIGEST_आकार;
      }
    हाल libcrux_sha3_Algorithm_Sha512:
      {
        वापस LIBCRUX_SHA3_SHA3_512_DIGEST_आकार;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __खाता__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  वापस LIBCRUX_SHA3_SHA3_224_DIGEST_आकार;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 144
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_block_9e(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start
)
{
  Eurydice_arr_7c state_flat = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)144U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार offset = start + (माप_प्रकार)8U * i0;
    Eurydice_array_u8x8 arr;
    स_नकल(arr.तथ्य,
      Eurydice_slice_subslice_shared_c8(blocks,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = offset, .end = offset + (माप_प्रकार)8U })).ptr,
      (माप_प्रकार)8U * माप (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_परिणाम_unwrap_26_e0((
          KRML_CLITERAL(core_परिणाम_परिणाम_8e){ .tag = core_परिणाम_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.तथ्य[i0] = core_अंक_u64_from_le_bytes(uu____0);
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)144U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_sha3_traits_set_ij_71(state,
      i0 / (माप_प्रकार)5U,
      i0 % (माप_प्रकार)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (माप_प्रकार)5U, i0 % (माप_प्रकार)5U)[0U] ^
        state_flat.तथ्य[i0]);
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_block_a1_9e(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_9e(self, निवेश->तथ्य[0U], start);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_block_80_e92(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_a1_9e(self, निवेश, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 144
- DELIMITER= 6
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_last_3a(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  Eurydice_arr_f4 बफर = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d44(&बफर,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = len })),
    Eurydice_slice_subslice_shared_c8(blocks,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = start, .end = start + len })),
    uint8_t);
  बफर.तथ्य[len] = 6U;
  माप_प्रकार uu____0 = (माप_प्रकार)144U - (माप_प्रकार)1U;
  बफर.तथ्य[uu____0] = (uint32_t)बफर.तथ्य[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_9e(state,
    Eurydice_array_to_slice_shared_38(&बफर),
    (माप_प्रकार)0U);
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_last_a1_3a(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_3a(self, निवेश->तथ्य[0U], start, len);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_final_80_bd3(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_a1_3a(self, निवेश, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 144
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_store_block_9e(
  स्थिर Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  माप_प्रकार octets = len / (माप_प्रकार)8U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < octets; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          i0 / (माप_प्रकार)5U,
          i0 % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + (माप_प्रकार)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + (माप_प्रकार)8U })),
      Eurydice_array_to_slice_shared_6e(&bytes),
      uint8_t);
  }
  माप_प्रकार remaining = len % (माप_प्रकार)8U;
  अगर (remaining > (माप_प्रकार)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          octets / (माप_प्रकार)5U,
          octets % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_21(&bytes, remaining),
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_squeeze_9b_9e(
  स्थिर Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_store_block_9e(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 144
- DELIM= 6
*/
अटल अंतरभूत व्योम
libcrux_sha3_generic_keccak_portable_keccak1_3a(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  माप_प्रकार निवेश_len = निवेश.meta;
  माप_प्रकार निवेश_blocks = निवेश_len / (माप_प्रकार)144U;
  माप_प्रकार निवेश_rem = निवेश_len % (माप_प्रकार)144U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < निवेश_blocks; i++)
  {
    माप_प्रकार i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
    libcrux_sha3_generic_keccak_absorb_block_80_e92(&s, &lvalue, i0 * (माप_प्रकार)144U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd3(&s, &lvalue, निवेश_len - निवेश_rem, निवेश_rem);
  माप_प्रकार output_len = output.meta;
  माप_प्रकार output_blocks = output_len / (माप_प्रकार)144U;
  माप_प्रकार output_rem = output_len % (माप_प्रकार)144U;
  अगर (output_blocks == (माप_प्रकार)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, (माप_प्रकार)0U, output_len);
  }
  अन्यथा
  {
    libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, (माप_प्रकार)0U, (माप_प्रकार)144U);
    क्रम (माप_प्रकार i = (माप_प्रकार)1U; i < output_blocks; i++)
    {
      माप_प्रकार i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, i0 * (माप_प्रकार)144U, (माप_प्रकार)144U);
    }
    अगर (output_rem != (माप_प्रकार)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 224 implementation.
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_sha224(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 तथ्य
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_3a(तथ्य, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 104
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_block_53(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start
)
{
  Eurydice_arr_7c state_flat = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)104U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार offset = start + (माप_प्रकार)8U * i0;
    Eurydice_array_u8x8 arr;
    स_नकल(arr.तथ्य,
      Eurydice_slice_subslice_shared_c8(blocks,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = offset, .end = offset + (माप_प्रकार)8U })).ptr,
      (माप_प्रकार)8U * माप (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_परिणाम_unwrap_26_e0((
          KRML_CLITERAL(core_परिणाम_परिणाम_8e){ .tag = core_परिणाम_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.तथ्य[i0] = core_अंक_u64_from_le_bytes(uu____0);
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)104U / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_sha3_traits_set_ij_71(state,
      i0 / (माप_प्रकार)5U,
      i0 % (माप_प्रकार)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (माप_प्रकार)5U, i0 % (माप_प्रकार)5U)[0U] ^
        state_flat.तथ्य[i0]);
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_block_a1_53(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_53(self, निवेश->तथ्य[0U], start);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_block_80_e93(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start
)
{
  libcrux_sha3_simd_portable_load_block_a1_53(self, निवेश, start);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 104
- DELIMITER= 6
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_load_last_dc0(
  Eurydice_arr_7c *state,
  Eurydice_borrow_slice_u8 blocks,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  Eurydice_arr_c4 बफर = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d45(&बफर,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = len })),
    Eurydice_slice_subslice_shared_c8(blocks,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = start, .end = start + len })),
    uint8_t);
  बफर.तथ्य[len] = 6U;
  माप_प्रकार uu____0 = (माप_प्रकार)104U - (माप_प्रकार)1U;
  बफर.तथ्य[uu____0] = (uint32_t)बफर.तथ्य[uu____0] | 128U;
  libcrux_sha3_simd_portable_load_block_53(state,
    Eurydice_array_to_slice_shared_72(&बफर),
    (माप_प्रकार)0U);
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_load_last_a1_dc0(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_dc0(self, निवेश->तथ्य[0U], start, len);
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_absorb_final_80_bd4(
  Eurydice_arr_7c *self,
  स्थिर Eurydice_arr_dc *निवेश,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_load_last_a1_dc0(self, निवेश, start, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 104
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_simd_portable_store_block_53(
  स्थिर Eurydice_arr_7c *s,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  माप_प्रकार octets = len / (माप_प्रकार)8U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < octets; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          i0 / (माप_प्रकार)5U,
          i0 % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + (माप_प्रकार)8U * i0;
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + (माप_प्रकार)8U })),
      Eurydice_array_to_slice_shared_6e(&bytes),
      uint8_t);
  }
  माप_प्रकार remaining = len % (माप_प्रकार)8U;
  अगर (remaining > (माप_प्रकार)0U)
  {
    Eurydice_array_u8x8
    bytes =
      core_अंक_u64_to_le_bytes(libcrux_sha3_traits_get_ij_71(s,
          octets / (माप_प्रकार)5U,
          octets % (माप_प्रकार)5U)[0U]);
    माप_प्रकार out_pos = start + len - remaining;
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_c8(out,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = out_pos, .end = out_pos + remaining }));
    Eurydice_slice_copy(uu____0,
      Eurydice_array_to_subslice_to_shared_21(&bytes, remaining),
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
अटल अंतरभूत व्योम
libcrux_sha3_simd_portable_squeeze_9b_53(
  स्थिर Eurydice_arr_7c *self,
  Eurydice_mut_borrow_slice_u8 out,
  माप_प्रकार start,
  माप_प्रकार len
)
{
  libcrux_sha3_simd_portable_store_block_53(self, out, start, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 104
- DELIM= 6
*/
अटल अंतरभूत व्योम
libcrux_sha3_generic_keccak_portable_keccak1_dc0(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_mut_borrow_slice_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  माप_प्रकार निवेश_len = निवेश.meta;
  माप_प्रकार निवेश_blocks = निवेश_len / (माप_प्रकार)104U;
  माप_प्रकार निवेश_rem = निवेश_len % (माप_प्रकार)104U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < निवेश_blocks; i++)
  {
    माप_प्रकार i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
    libcrux_sha3_generic_keccak_absorb_block_80_e93(&s, &lvalue, i0 * (माप_प्रकार)104U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd4(&s, &lvalue, निवेश_len - निवेश_rem, निवेश_rem);
  माप_प्रकार output_len = output.meta;
  माप_प्रकार output_blocks = output_len / (माप_प्रकार)104U;
  माप_प्रकार output_rem = output_len % (माप_प्रकार)104U;
  अगर (output_blocks == (माप_प्रकार)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, (माप_प्रकार)0U, output_len);
  }
  अन्यथा
  {
    libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, (माप_प्रकार)0U, (माप_प्रकार)104U);
    क्रम (माप_प्रकार i = (माप_प्रकार)1U; i < output_blocks; i++)
    {
      माप_प्रकार i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, i0 * (माप_प्रकार)104U, (माप_प्रकार)104U);
    }
    अगर (output_rem != (माप_प्रकार)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 384 implementation.
*/
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_portable_sha384(
  Eurydice_mut_borrow_slice_u8 digest,
  Eurydice_borrow_slice_u8 तथ्य
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_dc0(तथ्य, digest);
}

/**
 SHA3 224

 Preconditions:
 - `digest.len() == 28`
*/
अटल अंतरभूत व्योम
libcrux_sha3_sha224_ema(Eurydice_mut_borrow_slice_u8 digest, Eurydice_borrow_slice_u8 payload)
{
  libcrux_sha3_portable_sha224(digest, payload);
}

/**
 SHA3 224
*/
अटल अंतरभूत Eurydice_arr_a2 libcrux_sha3_sha224(Eurydice_borrow_slice_u8 तथ्य)
{
  Eurydice_arr_a2 out = { .तथ्य = { 0U } };
  libcrux_sha3_sha224_ema(Eurydice_array_to_slice_mut_5e(&out), तथ्य);
  वापस out;
}

/**
 SHA3 256
*/
अटल अंतरभूत व्योम
libcrux_sha3_sha256_ema(Eurydice_mut_borrow_slice_u8 digest, Eurydice_borrow_slice_u8 payload)
{
  libcrux_sha3_portable_sha256(digest, payload);
}

/**
 SHA3 256
*/
अटल अंतरभूत Eurydice_arr_ec libcrux_sha3_sha256(Eurydice_borrow_slice_u8 तथ्य)
{
  Eurydice_arr_ec out = { .तथ्य = { 0U } };
  libcrux_sha3_sha256_ema(Eurydice_array_to_slice_mut_01(&out), तथ्य);
  वापस out;
}

/**
 SHA3 384
*/
अटल अंतरभूत व्योम
libcrux_sha3_sha384_ema(Eurydice_mut_borrow_slice_u8 digest, Eurydice_borrow_slice_u8 payload)
{
  libcrux_sha3_portable_sha384(digest, payload);
}

/**
 SHA3 384
*/
अटल अंतरभूत Eurydice_arr_65 libcrux_sha3_sha384(Eurydice_borrow_slice_u8 तथ्य)
{
  Eurydice_arr_65 out = { .तथ्य = { 0U } };
  libcrux_sha3_sha384_ema(Eurydice_array_to_slice_mut_9f(&out), तथ्य);
  वापस out;
}

/**
 SHA3 512
*/
अटल अंतरभूत व्योम
libcrux_sha3_sha512_ema(Eurydice_mut_borrow_slice_u8 digest, Eurydice_borrow_slice_u8 payload)
{
  libcrux_sha3_portable_sha512(digest, payload);
}

/**
 SHA3 512
*/
अटल अंतरभूत Eurydice_arr_c7 libcrux_sha3_sha512(Eurydice_borrow_slice_u8 तथ्य)
{
  Eurydice_arr_c7 out = { .तथ्य = { 0U } };
  libcrux_sha3_sha512_ema(Eurydice_array_to_slice_mut_17(&out), तथ्य);
  वापस out;
}

/**
 SHAKE 128

 Writes `out.len()` bytes.
*/
अटल अंतरभूत व्योम
libcrux_sha3_shake128_ema(Eurydice_mut_borrow_slice_u8 out, Eurydice_borrow_slice_u8 तथ्य)
{
  libcrux_sha3_portable_shake128(out, तथ्य);
}

/**
 SHAKE 256

 Writes `out.len()` bytes.
*/
अटल अंतरभूत व्योम
libcrux_sha3_shake256_ema(Eurydice_mut_borrow_slice_u8 out, Eurydice_borrow_slice_u8 तथ्य)
{
  libcrux_sha3_portable_shake256(out, तथ्य);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $168size_t
*/
प्रकार काष्ठा libcrux_sha3_generic_keccak_xof_KeccakXofState_55_s
{
  Eurydice_arr_7c inner;
  Eurydice_arr_88 buf;
  माप_प्रकार buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_55;

प्रकार libcrux_sha3_generic_keccak_xof_KeccakXofState_55
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
अटल अंतरभूत माप_प्रकार
libcrux_sha3_generic_keccak_xof_fill_बफर_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  स्थिर Eurydice_arr_dc *inputs
)
{
  माप_प्रकार निवेश_len = inputs->तथ्य->meta;
  माप_प्रकार uu____0;
  अगर (self->buf_len != (माप_प्रकार)0U)
  {
    अगर (निवेश_len >= (माप_प्रकार)168U - self->buf_len)
    {
      माप_प्रकार consumed = (माप_प्रकार)168U - self->buf_len;
      क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)1U; i++)
      {
        माप_प्रकार i0 = i;
        Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_5f0(&self->buf.तथ्य[i0],
            self->buf_len),
          Eurydice_slice_subslice_to_shared_72(inputs->तथ्य[i0], consumed),
          uint8_t);
      }
      self->buf_len = (माप_प्रकार)168U;
      uu____0 = consumed;
    }
    अन्यथा
    {
      uu____0 = (माप_प्रकार)0U;
    }
  }
  अन्यथा
  {
    uu____0 = (माप_प्रकार)0U;
  }
  वापस uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $168size_t
*/
प्रकार स्थिर Eurydice_arr_88 *libcrux_sha3_generic_keccak_xof_buf_to_slices_closure_48;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_2a
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_2a_810(
  स्थिर Eurydice_arr_88 **_,
  माप_प्रकार tupled_args
)
{
  माप_प्रकार i = tupled_args;
  वापस
    core_array___T__N___as_slice((माप_प्रकार)168U,
      &_[0U]->तथ्य[i],
      uint8_t,
      Eurydice_borrow_slice_u8);
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
अटल अंतरभूत Eurydice_borrow_slice_u8
libcrux_sha3_generic_keccak_xof_buf_to_slices_call_once_fa_810(
  स्थिर Eurydice_arr_88 *_,
  माप_प्रकार _0
)
{
  वापस libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_2a_810(&_, _0);
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
अटल KRML_MUSTINLINE Eurydice_arr_dc
libcrux_sha3_generic_keccak_xof_buf_to_slices_810(स्थिर Eurydice_arr_88 *buf)
{
  Eurydice_arr_dc arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)1U; i++)
  {
    arr_struct.तथ्य[i] = libcrux_sha3_generic_keccak_xof_buf_to_slices_call_mut_2a_810(&buf, i);
  }
  वापस arr_struct;
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
अटल अंतरभूत माप_प्रकार
libcrux_sha3_generic_keccak_xof_absorb_full_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  स्थिर Eurydice_arr_dc *inputs
)
{
  माप_प्रकार consumed = libcrux_sha3_generic_keccak_xof_fill_बफर_35_e90(self, inputs);
  अगर (self->buf_len == (माप_प्रकार)168U)
  {
    Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_to_slices_810(&self->buf);
    libcrux_sha3_simd_portable_load_block_a1_60(&self->inner, &borrowed, (माप_प्रकार)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    self->buf_len = (माप_प्रकार)0U;
  }
  माप_प्रकार निवेश_to_consume = inputs->तथ्य->meta - consumed;
  माप_प्रकार अंक_blocks = निवेश_to_consume / (माप_प्रकार)168U;
  माप_प्रकार remainder = निवेश_to_consume % (माप_प्रकार)168U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < अंक_blocks; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार start = i0 * (माप_प्रकार)168U + consumed;
    libcrux_sha3_simd_portable_load_block_a1_60(&self->inner, inputs, start);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
  }
  वापस remainder;
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_xof_absorb_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  स्थिर Eurydice_arr_dc *inputs
)
{
  माप_प्रकार remainder = libcrux_sha3_generic_keccak_xof_absorb_full_35_e90(self, inputs);
  अगर (remainder > (माप_प्रकार)0U)
  {
    माप_प्रकार निवेश_len = inputs->तथ्य->meta;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)1U; i++)
    {
      माप_प्रकार i0 = i;
      Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d41(&self->buf.तथ्य[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .start = self->buf_len,
              .end = self->buf_len + remainder
            }
          )),
        Eurydice_slice_subslice_shared_c8(inputs->तथ्य[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .start = निवेश_len - remainder,
              .end = निवेश_len
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
अटल अंतरभूत व्योम
libcrux_sha3_portable_incremental_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_borrow_slice_u8 निवेश
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_xof_absorb_final_35_bd0(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  स्थिर Eurydice_arr_dc *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_e90(self, inputs);
  Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_to_slices_810(&self->buf);
  libcrux_sha3_simd_portable_load_last_a1_37(&self->inner, &borrowed, (माप_प्रकार)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
अटल अंतरभूत व्योम
libcrux_sha3_portable_incremental_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_borrow_slice_u8 निवेश
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .तथ्य = { निवेश } };
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
अटल अंतरभूत Eurydice_arr_c5 libcrux_sha3_generic_keccak_xof_zero_block_35_e90(व्योम)
{
  वापस (KRML_CLITERAL(Eurydice_arr_c5){ .तथ्य = { 0U } });
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
अटल अंतरभूत libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_generic_keccak_xof_new_35_e90(व्योम)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_71();
  Eurydice_arr_c5 repeat_expression[1U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)1U; i++)
  {
    repeat_expression[i] = libcrux_sha3_generic_keccak_xof_zero_block_35_e90();
  }
  स_नकल(lit.buf.तथ्य, repeat_expression, (माप_प्रकार)1U * माप (Eurydice_arr_c5));
  lit.buf_len = (माप_प्रकार)0U;
  lit.sponge = false;
  वापस lit;
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
अटल अंतरभूत libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_portable_incremental_new_26(व्योम)
{
  वापस libcrux_sha3_generic_keccak_xof_new_35_e90();
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
अटल KRML_MUSTINLINE व्योम
libcrux_sha3_generic_keccak_xof_squeeze_85_2a(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  माप_प्रकार out_len = out.meta;
  अगर (!(out_len == (माप_प्रकार)0U))
  {
    अगर (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    }
    अगर (out_len > (माप_प्रकार)0U)
    {
      माप_प्रकार blocks = out_len / (माप_प्रकार)168U;
      माप_प्रकार last = out_len - out_len % (माप_प्रकार)168U;
      अगर (blocks == (माप_प्रकार)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, out, (माप_प्रकार)0U, out_len);
      }
      अन्यथा
      {
        libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, out, (माप_प्रकार)0U, (माप_प्रकार)168U);
        क्रम (माप_प्रकार i = (माप_प्रकार)1U; i < blocks; i++)
        {
          माप_प्रकार i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner,
            out,
            i0 * (माप_प्रकार)168U,
            (माप_प्रकार)168U);
        }
        अगर (last < out_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, out, last, out_len - last);
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
अटल अंतरभूत व्योम
libcrux_sha3_portable_incremental_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_2a(self, out);
}

/**
This function found in impl {core::clone::Clone for libcrux_sha3::portable::KeccakState}
*/
अटल अंतरभूत Eurydice_arr_7c libcrux_sha3_portable_clone_fe(स्थिर Eurydice_arr_7c *self)
{
  वापस self[0U];
}

/**
This function found in impl {core::clone::Clone for libcrux_sha3::Algorithm}
*/
अटल अंतरभूत libcrux_sha3_Algorithm libcrux_sha3_clone_e6(स्थिर libcrux_sha3_Algorithm *self)
{
  वापस self[0U];
}

/**
This function found in impl {core::convert::From<libcrux_sha3::Algorithm> for u32}
*/
अटल अंतरभूत uint32_t libcrux_sha3_from_6c(libcrux_sha3_Algorithm v)
{
  चयन (v)
  {
    हाल libcrux_sha3_Algorithm_Sha224:
      {
        अवरोध;
      }
    हाल libcrux_sha3_Algorithm_Sha256:
      {
        वापस 2U;
      }
    हाल libcrux_sha3_Algorithm_Sha384:
      {
        वापस 3U;
      }
    हाल libcrux_sha3_Algorithm_Sha512:
      {
        वापस 4U;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __खाता__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  वापस 1U;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_sha3_portable_KeccakState
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_1b0_s { Eurydice_arr_7c तथ्य[3U]; } Eurydice_arr_1b0;

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा libcrux_sha3_portable_H_DEFINED
#पूर्ण_अगर /* libcrux_sha3_portable_H */

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


#अगर_अघोषित libcrux_mlkem_core_H
#घोषणा libcrux_mlkem_core_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


#घोषणा LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार ((माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_COEFFICIENT ((माप_प्रकार)12U)

#घोषणा LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT ((माप_प्रकार)256U)

#घोषणा LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (माप_प्रकार)12U)

#घोषणा LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_RING_ELEMENT / (माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_कुंजी_GENERATION_SEED_आकार ((माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_KEM_CONSTANTS_G_DIGEST_आकार ((माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_आकार ((माप_प्रकार)32U)

/**
 K * BITS_PER_RING_ELEMENT / 8

 [eurydice] Note that we can't use const generics here because that breaks
            C extraction with eurydice.
*/
अटल अंतरभूत माप_प्रकार libcrux_ml_kem_constants_ranked_bytes_per_ring_element(माप_प्रकार rank)
{
  वापस rank * LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_RING_ELEMENT / (माप_प्रकार)8U;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
अटल KRML_MUSTINLINE uint8_t libcrux_secrets_int_as_u8_f5(int16_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_90((uint8_t)libcrux_secrets_int_public_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u8}
*/
अटल KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_59(uint8_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_39((int16_t)(uint32_t)libcrux_secrets_int_public_integers_declassify_d8_90(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
अटल KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_f5(int16_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_a8((int32_t)libcrux_secrets_int_public_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i32}
*/
अटल KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_36(int32_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_39((int16_t)libcrux_secrets_int_public_integers_declassify_d8_a8(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
अटल KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_b8(uint32_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_a8((int32_t)libcrux_secrets_int_public_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
अटल KRML_MUSTINLINE uint16_t libcrux_secrets_int_as_u16_f5(int16_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_de((uint16_t)libcrux_secrets_int_public_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
अटल KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_ca(uint16_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_39((int16_t)(uint32_t)libcrux_secrets_int_public_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
अटल KRML_MUSTINLINE uint64_t libcrux_secrets_int_as_u64_ca(uint16_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_49((uint64_t)(uint32_t)libcrux_secrets_int_public_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u64}
*/
अटल KRML_MUSTINLINE uint32_t libcrux_secrets_int_as_u32_a3(uint64_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_df((uint32_t)libcrux_secrets_int_public_integers_declassify_d8_49(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
अटल KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_b8(uint32_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_39((int16_t)libcrux_secrets_int_public_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
अटल KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_f5(int16_t self)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_39(libcrux_secrets_int_public_integers_declassify_d8_39(self));
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 32
*/
अटल KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_utils_into_padded_array_ce(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_ec out = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d46(&out,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = slice.meta })),
    slice,
    uint8_t);
  वापस out;
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.default_d3
with const generics
- SIZE= 2400
*/
अटल अंतरभूत Eurydice_arr_7d libcrux_ml_kem_types_default_d3_79(व्योम)
{
  वापस (KRML_CLITERAL(Eurydice_arr_7d){ .तथ्य = { 0U } });
}

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemPublicKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_51
with const generics
- SIZE= 1184
*/
अटल अंतरभूत Eurydice_arr_5f libcrux_ml_kem_types_from_51_3d(Eurydice_arr_5f मूल्य)
{
  वापस मूल्य;
}

प्रकार काष्ठा libcrux_ml_kem_mlkem768_Ml_Kem768_कुंजी_Pair_s
{
  Eurydice_arr_7d sk;
  Eurydice_arr_5f pk;
}
libcrux_ml_kem_mlkem768_Ml_Kem768_कुंजी_Pair;

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
अटल अंतरभूत libcrux_ml_kem_mlkem768_Ml_Kem768_कुंजी_Pair
libcrux_ml_kem_types_from_17_bc(Eurydice_arr_7d sk, Eurydice_arr_5f pk)
{
  वापस (KRML_CLITERAL(libcrux_ml_kem_mlkem768_Ml_Kem768_कुंजी_Pair){ .sk = sk, .pk = pk });
}

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_b2
with const generics
- SIZE= 2400
*/
अटल अंतरभूत Eurydice_arr_7d libcrux_ml_kem_types_from_b2_79(Eurydice_arr_7d मूल्य)
{
  वापस मूल्य;
}

/**
A monomorphic instance of n-tuple
with types libcrux_ml_kem_mlkem768_MlKem768Ciphertext, Eurydice_arr_ec

*/
प्रकार काष्ठा tuple_f4_s
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
अटल अंतरभूत Eurydice_arr_2b libcrux_ml_kem_types_from_19_52(Eurydice_arr_2b मूल्य)
{
  वापस मूल्य;
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
अटल अंतरभूत स्थिर
Eurydice_arr_5f
*libcrux_ml_kem_types_as_slice_e6_3d(स्थिर Eurydice_arr_5f *self)
{
  वापस self;
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
अटल अंतरभूत स्थिर
Eurydice_arr_2b
*libcrux_ml_kem_types_as_slice_a9_52(स्थिर Eurydice_arr_2b *self)
{
  वापस self;
}

/**
A monomorphic instance of libcrux_ml_kem.utils.prf_input_inc
with const generics
- K= 3
*/
अटल KRML_MUSTINLINE uint8_t
libcrux_ml_kem_utils_prf_निवेश_inc_78(Eurydice_arr_fd *prf_inputs, uint8_t domain_separator)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    prf_inputs->तथ्य[i0].तथ्य[32U] = domain_separator;
    domain_separator = (uint32_t)domain_separator + 1U;
  }
  वापस domain_separator;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 33
*/
अटल KRML_MUSTINLINE Eurydice_arr_fa0
libcrux_ml_kem_utils_into_padded_array_29(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_fa0 out = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d412(&out,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = slice.meta })),
    slice,
    uint8_t);
  वापस out;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 34
*/
अटल KRML_MUSTINLINE Eurydice_arr_31
libcrux_ml_kem_utils_into_padded_array_de(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_31 out = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d40(&out,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = slice.meta })),
    slice,
    uint8_t);
  वापस out;
}

/**
This function found in impl {core::convert::AsRef<[u8]> for libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_ref_c1
with const generics
- SIZE= 1088
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
libcrux_ml_kem_types_as_ref_c1_52(स्थिर Eurydice_arr_2b *self)
{
  वापस Eurydice_array_to_slice_shared_06(self);
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 1120
*/
अटल KRML_MUSTINLINE Eurydice_arr_af
libcrux_ml_kem_utils_into_padded_array_66(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_af out = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d411(&out,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = slice.meta })),
    slice,
    uint8_t);
  वापस out;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 64
*/
अटल KRML_MUSTINLINE Eurydice_arr_c7
libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_borrow_slice_u8 slice)
{
  Eurydice_arr_c7 out = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d410(&out,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = slice.meta })),
    slice,
    uint8_t);
  वापस out;
}

प्रकार काष्ठा Eurydice_borrow_slice_u8_x4_s
{
  Eurydice_borrow_slice_u8 fst;
  Eurydice_borrow_slice_u8 snd;
  Eurydice_borrow_slice_u8 thd;
  Eurydice_borrow_slice_u8 f3;
}
Eurydice_borrow_slice_u8_x4;

प्रकार काष्ठा Eurydice_borrow_slice_u8_x2_s
{
  Eurydice_borrow_slice_u8 fst;
  Eurydice_borrow_slice_u8 snd;
}
Eurydice_borrow_slice_u8_x2;

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
अटल अंतरभूत Eurydice_borrow_slice_u8_x4
libcrux_ml_kem_types_unpack_private_कुंजी_64(Eurydice_borrow_slice_u8 private_कुंजी)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(private_कुंजी,
      (माप_प्रकार)1152U,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 ind_cpa_secret_कुंजी = uu____0.fst;
  Eurydice_borrow_slice_u8 secret_key0 = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(secret_key0,
      (माप_प्रकार)1184U,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 ind_cpa_public_कुंजी = uu____1.fst;
  Eurydice_borrow_slice_u8 secret_कुंजी = uu____1.snd;
  Eurydice_borrow_slice_u8_x2
  uu____2 =
    Eurydice_slice_split_at(secret_कुंजी,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 ind_cpa_public_कुंजी_hash = uu____2.fst;
  Eurydice_borrow_slice_u8 implicit_rejection_मूल्य = uu____2.snd;
  वापस
    (
      KRML_CLITERAL(Eurydice_borrow_slice_u8_x4){
        .fst = ind_cpa_secret_कुंजी,
        .snd = ind_cpa_public_कुंजी,
        .thd = ind_cpa_public_कुंजी_hash,
        .f3 = implicit_rejection_मूल्य
      }
    );
}

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा libcrux_mlkem_core_H_DEFINED
#पूर्ण_अगर /* libcrux_mlkem_core_H */

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


#अगर_अघोषित libcrux_mldsa_core_H
#घोषणा libcrux_mldsa_core_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


#घोषणा libcrux_ml_dsa_constants_Eta_Two 2
#घोषणा libcrux_ml_dsa_constants_Eta_Four 4

प्रकार uint8_t libcrux_ml_dsa_constants_Eta;

#घोषणा LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT ((माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_IN_RING_ELEMENT ((माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T ((माप_प्रकार)13U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS_MINUS_ONE_BIT_लंबाई ((माप_प्रकार)23U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_UPPER_PART_OF_T (LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS_MINUS_ONE_BIT_लंबाई - LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_कुंजी_HASH ((माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT ((माप_प्रकार)256U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN ((माप_प्रकार)255U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS (8380417)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V261_888 (261888)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V95_232 (95232)

प्रकार int32_t libcrux_ml_dsa_constants_Gamma2;

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_कुंजी_GENERATION_RANDOMNESS_आकार ((माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_MASK_SEED_आकार ((माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_MESSAGE_REPRESENTATIVE_आकार ((माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN ((माप_प्रकार)814U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0_S_आकार (LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT / (माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1_S_आकार (LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_UPPER_PART_OF_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT / (माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार ((माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_ERROR_VECTORS_आकार ((माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_आकार ((माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_SIGNING_RANDOMNESS_आकार ((माप_प्रकार)32U)

अटल अंतरभूत int32_t
libcrux_ml_dsa_constants_beta(
  माप_प्रकार ones_in_verifier_challenge,
  libcrux_ml_dsa_constants_Eta eta
)
{
  माप_प्रकार eta_val;
  चयन (eta)
  {
    हाल libcrux_ml_dsa_constants_Eta_Two:
      {
        eta_val = (माप_प्रकार)2U;
        अवरोध;
      }
    हाल libcrux_ml_dsa_constants_Eta_Four:
      {
        eta_val = (माप_प्रकार)4U;
        अवरोध;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __खाता__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  वापस (int32_t)(ones_in_verifier_challenge * eta_val);
}

अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_constants_commitment_ring_element_आकार(माप_प्रकार bits_per_commitment_coefficient)
{
  वापस
    bits_per_commitment_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT /
      (माप_प्रकार)8U;
}

अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_constants_commitment_vector_आकार(
  माप_प्रकार bits_per_commitment_coefficient,
  माप_प्रकार rows_in_a
)
{
  वापस
    libcrux_ml_dsa_constants_commitment_ring_element_आकार(bits_per_commitment_coefficient) *
      rows_in_a;
}

अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_constants_error_ring_element_आकार(माप_प्रकार bits_per_error_coefficient)
{
  वापस
    bits_per_error_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT / (माप_प्रकार)8U;
}

अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_constants_gamma1_ring_element_आकार(माप_प्रकार bits_per_gamma1_coefficient)
{
  वापस
    bits_per_gamma1_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT /
      (माप_प्रकार)8U;
}

अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_constants_signature_आकार(
  माप_प्रकार rows_in_a,
  माप_प्रकार columns_in_a,
  माप_प्रकार max_ones_in_hint,
  माप_प्रकार commitment_hash_आकार,
  माप_प्रकार bits_per_gamma1_coefficient
)
{
  वापस
    commitment_hash_आकार +
      columns_in_a * libcrux_ml_dsa_constants_gamma1_ring_element_आकार(bits_per_gamma1_coefficient)
    + max_ones_in_hint
    + rows_in_a;
}

अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_constants_signing_कुंजी_आकार(
  माप_प्रकार rows_in_a,
  माप_प्रकार columns_in_a,
  माप_प्रकार error_ring_element_आकार
)
{
  वापस
    LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार + LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_आकार +
      LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_कुंजी_HASH
    + (rows_in_a + columns_in_a) * error_ring_element_आकार
    + rows_in_a * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0_S_आकार;
}

अटल अंतरभूत माप_प्रकार libcrux_ml_dsa_constants_verification_कुंजी_आकार(माप_प्रकार rows_in_a)
{
  वापस
    LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार +
      LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * rows_in_a *
        (LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS_MINUS_ONE_BIT_लंबाई -
          LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T)
      / (माप_प्रकार)8U;
}

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_BITS_PER_COMMITMENT_COEFFICIENT ((माप_प्रकार)6U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_BITS_PER_ERROR_COEFFICIENT ((माप_प्रकार)3U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_BITS_PER_GAMMA1_COEFFICIENT ((माप_प्रकार)18U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A ((माप_प्रकार)4U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_आकार ((माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA (libcrux_ml_dsa_constants_Eta_Two)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT ((माप_प्रकार)17U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS - 1) / 88)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_IN_HINT ((माप_प्रकार)80U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_IN_VERIFIER_CHALLENGE ((माप_प्रकार)39U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A ((माप_प्रकार)4U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_COMMITMENT_COEFFICIENT ((माप_प्रकार)4U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_ERROR_COEFFICIENT ((माप_प्रकार)4U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_GAMMA1_COEFFICIENT ((माप_प्रकार)20U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A ((माप_प्रकार)5U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_आकार ((माप_प्रकार)48U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA (libcrux_ml_dsa_constants_Eta_Four)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT ((माप_प्रकार)19U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS - 1) / 32)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT ((माप_प्रकार)55U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_IN_VERIFIER_CHALLENGE ((माप_प्रकार)49U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A ((माप_प्रकार)6U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_BITS_PER_COMMITMENT_COEFFICIENT ((माप_प्रकार)4U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_BITS_PER_ERROR_COEFFICIENT ((माप_प्रकार)3U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_BITS_PER_GAMMA1_COEFFICIENT ((माप_प्रकार)20U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A ((माप_प्रकार)7U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_आकार ((माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA (libcrux_ml_dsa_constants_Eta_Two)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT ((माप_प्रकार)19U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS - 1) / 32)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_IN_HINT ((माप_प्रकार)75U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_IN_VERIFIER_CHALLENGE ((माप_प्रकार)60U)

#घोषणा LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A ((माप_प्रकार)8U)

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::constants::Eta}
*/
अटल अंतरभूत libcrux_ml_dsa_constants_Eta
libcrux_ml_dsa_constants_clone_54(स्थिर libcrux_ml_dsa_constants_Eta *self)
{
  वापस self[0U];
}

अटल KRML_MUSTINLINE माप_प्रकार
libcrux_ml_dsa_encoding_error_chunk_आकार(libcrux_ml_dsa_constants_Eta eta)
{
  चयन (eta)
  {
    हाल libcrux_ml_dsa_constants_Eta_Two:
      {
        अवरोध;
      }
    हाल libcrux_ml_dsa_constants_Eta_Four:
      {
        वापस (माप_प्रकार)4U;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __खाता__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  वापस (माप_प्रकार)3U;
}

#घोषणा libcrux_ml_dsa_types_VerificationError_MalformedHintError 0
#घोषणा libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError 1
#घोषणा libcrux_ml_dsa_types_VerificationError_CommitmentHashesDontMatchError 2
#घोषणा libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError 3

प्रकार uint8_t libcrux_ml_dsa_types_VerificationError;

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_signature_set_hint(
  Eurydice_dst_ref_mut_20 out_hint,
  माप_प्रकार i,
  माप_प्रकार j
)
{
  out_hint.ptr[i].तथ्य[j] = 1;
}

#घोषणा LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT ((माप_प्रकार)13U)

#घोषणा LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_WINDOW ((माप_प्रकार)10U)

#घोषणा LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_BYTES_PER_SIMD_UNIT ((माप_प्रकार)10U)

#घोषणा LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_BLOCK_आकार ((माप_प्रकार)168U)

#घोषणा LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_FIVE_BLOCKS_आकार (LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_BLOCK_आकार * (माप_प्रकार)5U)

#घोषणा LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE256_BLOCK_आकार ((माप_प्रकार)136U)

अटल KRML_MUSTINLINE Eurydice_arr_91
libcrux_ml_dsa_sample_add_error_domain_separator(
  Eurydice_borrow_slice_u8 slice,
  uint16_t domain_separator
)
{
  Eurydice_arr_91 out = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d4(&out,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = slice.meta })),
    slice,
    uint8_t);
  out.तथ्य[64U] = (uint8_t)(uint32_t)domain_separator;
  out.तथ्य[65U] = (uint8_t)((uint32_t)domain_separator >> 8U & 0xFFFFU);
  वापस out;
}

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_आकार (libcrux_ml_dsa_constants_error_ring_element_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_BITS_PER_ERROR_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS (8380417)

#घोषणा LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_OF_MODULUS_MOD_MONTGOMERY_R (58728449ULL)

अटल अंतरभूत uint8_t_x2
libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(माप_प्रकार index, माप_प्रकार width)
{
  वापस
    (KRML_CLITERAL(uint8_t_x2){ .fst = (uint8_t)(index / width), .snd = (uint8_t)(index % width) });
}

अटल KRML_MUSTINLINE uint16_t libcrux_ml_dsa_sample_generate_domain_separator(uint8_t_x2 _)
{
  uint8_t row = _.fst;
  uint8_t column = _.snd;
  वापस (uint32_t)(uint16_t)(uint32_t)column | (uint32_t)(uint16_t)(uint32_t)row << 8U;
}

अटल KRML_MUSTINLINE Eurydice_arr_31
libcrux_ml_dsa_sample_add_domain_separator(Eurydice_borrow_slice_u8 slice, uint8_t_x2 indices)
{
  Eurydice_arr_31 out = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d40(&out,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = slice.meta })),
    slice,
    uint8_t);
  uint16_t domain_separator = libcrux_ml_dsa_sample_generate_domain_separator(indices);
  out.तथ्य[32U] = (uint8_t)(uint32_t)domain_separator;
  out.तथ्य[33U] = (uint8_t)((uint32_t)domain_separator >> 8U & 0xFFFFU);
  वापस out;
}

#घोषणा libcrux_ml_dsa_types_SigningError_RejectionSamplingError 0
#घोषणा libcrux_ml_dsa_types_SigningError_ContextTooLongError 1

प्रकार uint8_t libcrux_ml_dsa_types_SigningError;

प्रकार काष्ठा libcrux_ml_dsa_pre_hash_DomainSeparationContext_s
{
  Eurydice_borrow_slice_u8 context;
  core_option_Option_57 pre_hash_oid;
}
libcrux_ml_dsa_pre_hash_DomainSeparationContext;

#घोषणा libcrux_ml_dsa_pre_hash_DomainSeparationError_ContextTooLongError 0

प्रकार uint8_t libcrux_ml_dsa_pre_hash_DomainSeparationError;

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext, libcrux_ml_dsa_pre_hash_DomainSeparationError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_a8_s
{
  core_परिणाम_परिणाम_57_tags tag;
  जोड़ {
    libcrux_ml_dsa_pre_hash_DomainSeparationContext case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationError case_Err;
  }
  val;
}
core_परिणाम_परिणाम_a8;

/**
 `context` must be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
अटल अंतरभूत core_परिणाम_परिणाम_a8
libcrux_ml_dsa_pre_hash_new_88(
  Eurydice_borrow_slice_u8 context,
  core_option_Option_57 pre_hash_oid
)
{
  अगर (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_a8){
          .tag = core_परिणाम_Ok,
          .val = { .case_Ok = { .context = context, .pre_hash_oid = pre_hash_oid } }
        }
      );
  }
  वापस
    (
      KRML_CLITERAL(core_परिणाम_परिणाम_a8){
        .tag = core_परिणाम_Err,
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
अटल अंतरभूत स्थिर
core_option_Option_57
*libcrux_ml_dsa_pre_hash_pre_hash_oid_88(
  स्थिर libcrux_ml_dsa_pre_hash_DomainSeparationContext *self
)
{
  वापस &self->pre_hash_oid;
}

/**
 Returns the context, guaranteed to be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
अटल अंतरभूत Eurydice_borrow_slice_u8
libcrux_ml_dsa_pre_hash_context_88(स्थिर libcrux_ml_dsa_pre_hash_DomainSeparationContext *self)
{
  वापस self->context;
}

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_आकार (libcrux_ml_dsa_constants_commitment_ring_element_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_BITS_PER_COMMITMENT_COEFFICIENT))

अटल KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_inside_out_shuffle(
  Eurydice_borrow_slice_u8 randomness,
  माप_प्रकार *out_सूचकांक,
  uint64_t *signs,
  Eurydice_arr_6c *परिणाम
)
{
  bool done = false;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < randomness.meta; i++)
  {
    माप_प्रकार _cloop_j = i;
    स्थिर uint8_t *byte = &randomness.ptr[_cloop_j];
    अगर (!done)
    {
      माप_प्रकार sample_at = (माप_प्रकार)(uint32_t)byte[0U];
      अगर (sample_at <= out_सूचकांक[0U])
      {
        परिणाम->तथ्य[out_सूचकांक[0U]] = परिणाम->तथ्य[sample_at];
        out_सूचकांक[0U]++;
        परिणाम->तथ्य[sample_at] = 1 - 2 * (int32_t)(signs[0U] & 1ULL);
        signs[0U] >>= 1U;
      }
      done = out_सूचकांक[0U] == (माप_प्रकार)256U;
    }
  }
  वापस done;
}

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_IN_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_आकार (libcrux_ml_dsa_constants_gamma1_ring_element_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_BITS_PER_GAMMA1_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID ((KRML_CLITERAL(Eurydice_arr_c9){ .तथ्य = { 6U, 9U, 96U, 134U, 72U, 1U, 101U, 3U, 4U, 2U, 11U } }))

/**
This function found in impl {libcrux_ml_dsa::pre_hash::PreHash for libcrux_ml_dsa::pre_hash::SHAKE128_PH}
*/
अटल अंतरभूत Eurydice_arr_c9 libcrux_ml_dsa_pre_hash_oid_30(व्योम)
{
  वापस LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID;
}

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_VERIFICATION_कुंजी_आकार (libcrux_ml_dsa_constants_verification_कुंजी_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNATURE_आकार (libcrux_ml_dsa_constants_signature_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_IN_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_आकार, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_BITS_PER_GAMMA1_COEFFICIENT))

प्रकार Eurydice_arr_4d libcrux_ml_dsa_simd_portable_vector_type_Coefficients;

अटल KRML_MUSTINLINE Eurydice_arr_4d libcrux_ml_dsa_simd_portable_vector_type_zero(व्योम)
{
  वापस (KRML_CLITERAL(Eurydice_arr_4d){ .तथ्य = { 0U } });
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत Eurydice_arr_4d libcrux_ml_dsa_simd_portable_zero_65(व्योम)
{
  वापस libcrux_ml_dsa_simd_portable_vector_type_zero();
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_vector_type_from_coefficient_array(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_4d *out
)
{
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_fd(out),
    Eurydice_slice_subslice_shared_47(array,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)0U,
          .end = LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT
        }
      )),
    int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_from_coefficient_array_65(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_4d *out
)
{
  libcrux_ml_dsa_simd_portable_vector_type_from_coefficient_array(array, out);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_vector_type_to_coefficient_array(
  स्थिर Eurydice_arr_4d *मूल्य,
  Eurydice_dst_ref_mut_83 out
)
{
  Eurydice_slice_copy(out, Eurydice_array_to_slice_shared_fd(मूल्य), int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_to_coefficient_array_65(
  स्थिर Eurydice_arr_4d *मूल्य,
  Eurydice_dst_ref_mut_83 out
)
{
  libcrux_ml_dsa_simd_portable_vector_type_to_coefficient_array(मूल्य, out);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_arithmetic_add(Eurydice_arr_4d *lhs, स्थिर Eurydice_arr_4d *rhs)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार uu____0 = i0;
    lhs->तथ्य[uu____0] += rhs->तथ्य[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_add_65(Eurydice_arr_4d *lhs, स्थिर Eurydice_arr_4d *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_add(lhs, rhs);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_arithmetic_subtract(
  Eurydice_arr_4d *lhs,
  स्थिर Eurydice_arr_4d *rhs
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार uu____0 = i0;
    lhs->तथ्य[uu____0] -= rhs->तथ्य[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_subtract_65(Eurydice_arr_4d *lhs, स्थिर Eurydice_arr_4d *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_subtract(lhs, rhs);
}

अटल KRML_MUSTINLINE bool
libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(
  स्थिर Eurydice_arr_4d *simd_unit,
  int32_t bound
)
{
  bool परिणाम = false;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    int32_t coefficient = simd_unit->तथ्य[i0];
    int32_t sign = coefficient >> 31U;
    int32_t normalized = coefficient - (sign & 2 * coefficient);
    bool uu____0;
    अगर (परिणाम)
    {
      uu____0 = true;
    }
    अन्यथा
    {
      uu____0 = normalized >= bound;
    }
    परिणाम = uu____0;
  }
  वापस परिणाम;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत bool
libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(
  स्थिर Eurydice_arr_4d *simd_unit,
  int32_t bound
)
{
  वापस libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(simd_unit, bound);
}

अटल KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(int32_t gamma2, int32_t r)
{
  int32_t r0 = r + (r >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS);
  int32_t ceil_of_r_by_128 = (r0 + 127) >> 7U;
  int32_t r1;
  चयन (gamma2)
  {
    हाल 95232:
      {
        int32_t परिणाम = (ceil_of_r_by_128 * 11275 + (int32_t)((uint32_t)1 << 23U)) >> 24U;
        int32_t परिणाम_0 = (परिणाम ^ (43 - परिणाम) >> 31U) & परिणाम;
        r1 = परिणाम_0;
        अवरोध;
      }
    हाल 261888:
      {
        int32_t परिणाम = (ceil_of_r_by_128 * 1025 + (int32_t)((uint32_t)1 << 21U)) >> 22U;
        int32_t परिणाम_0 = परिणाम & 15;
        r1 = परिणाम_0;
        अवरोध;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  int32_t alpha = gamma2 * 2;
  int32_t r00 = r0 - r1 * alpha;
  r00 -=
    ((LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS - 1) / 2 - r00) >> 31U &
      LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS;
  वापस (KRML_CLITERAL(int32_t_x2){ .fst = r00, .snd = r1 });
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_arithmetic_decompose(
  int32_t gamma2,
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *निचला,
  Eurydice_arr_4d *ऊपरी
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    int32_t_x2
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2,
        simd_unit->तथ्य[i0]);
    int32_t uu____1 = uu____0.snd;
    निचला->तथ्य[i0] = uu____0.fst;
    ऊपरी->तथ्य[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_decompose_65(
  int32_t gamma2,
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *निचला,
  Eurydice_arr_4d *ऊपरी
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_decompose(gamma2, simd_unit, निचला, ऊपरी);
}

अटल KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(
  int32_t निचला,
  int32_t ऊपरी,
  int32_t gamma2
)
{
  int32_t uu____0;
  अगर (निचला > gamma2)
  {
    uu____0 = 1;
  }
  अन्यथा अगर (निचला < -gamma2)
  {
    uu____0 = 1;
  }
  अन्यथा अगर (निचला == -gamma2)
  {
    अगर (ऊपरी != 0)
    {
      uu____0 = 1;
    }
    अन्यथा
    {
      uu____0 = 0;
    }
  }
  अन्यथा
  {
    uu____0 = 0;
  }
  वापस uu____0;
}

अटल KRML_MUSTINLINE माप_प्रकार
libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(
  स्थिर Eurydice_arr_4d *निचला,
  स्थिर Eurydice_arr_4d *ऊपरी,
  int32_t gamma2,
  Eurydice_arr_4d *hint
)
{
  माप_प्रकार one_hints_गिनती = (माप_प्रकार)0U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    hint->तथ्य[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(निचला->तथ्य[i0],
        ऊपरी->तथ्य[i0],
        gamma2);
    one_hints_गिनती += (माप_प्रकार)hint->तथ्य[i0];
  }
  वापस one_hints_गिनती;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_simd_portable_compute_hint_65(
  स्थिर Eurydice_arr_4d *निचला,
  स्थिर Eurydice_arr_4d *ऊपरी,
  int32_t gamma2,
  Eurydice_arr_4d *hint
)
{
  वापस libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(निचला, ऊपरी, gamma2, hint);
}

अटल KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(int32_t gamma2, int32_t r, int32_t hint)
{
  int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2, r);
  int32_t r0 = uu____0.fst;
  int32_t r1 = uu____0.snd;
  int32_t uu____1;
  अगर (!(hint == 0))
  {
    चयन (gamma2)
    {
      हाल 95232:
        {
          अगर (r0 > 0)
          {
            अगर (r1 == 43)
            {
              uu____1 = 0;
            }
            अन्यथा
            {
              uu____1 = r1 + hint;
            }
          }
          अन्यथा अगर (r1 == 0)
          {
            uu____1 = 43;
          }
          अन्यथा
          {
            uu____1 = r1 - hint;
          }
          अवरोध;
        }
      हाल 261888:
        {
          अगर (r0 > 0)
          {
            uu____1 = (r1 + hint) & 15;
          }
          अन्यथा
          {
            uu____1 = (r1 - hint) & 15;
          }
          अवरोध;
        }
      शेष:
        {
          KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "panic!");
          KRML_HOST_EXIT(255U);
        }
    }
    वापस uu____1;
  }
  वापस r1;
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_arithmetic_use_hint(
  int32_t gamma2,
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *hint
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    int32_t
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(gamma2,
        simd_unit->तथ्य[i0],
        hint->तथ्य[i0]);
    hint->तथ्य[i0] = uu____0;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_use_hint_65(
  int32_t gamma2,
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *hint
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_use_hint(gamma2, simd_unit, hint);
}

अटल KRML_MUSTINLINE uint64_t
libcrux_ml_dsa_simd_portable_arithmetic_get_n_least_significant_bits(uint8_t n, uint64_t मूल्य)
{
  वापस मूल्य & ((1ULL << (uint32_t)n) - 1ULL);
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT (32U)

अटल KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element(int64_t मूल्य)
{
  uint64_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_get_n_least_significant_bits(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT,
      (uint64_t)मूल्य)
    * LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_OF_MODULUS_MOD_MONTGOMERY_R;
  int32_t
  k =
    (int32_t)libcrux_ml_dsa_simd_portable_arithmetic_get_n_least_significant_bits(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT,
      t);
  int64_t k_times_modulus = (int64_t)k * (int64_t)LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS;
  int32_t
  c =
    (int32_t)(k_times_modulus >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT);
  int32_t
  मूल्य_ऊपरी =
    (int32_t)(मूल्य >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT);
  वापस मूल्य_ऊपरी - c;
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(
  Eurydice_arr_4d *lhs,
  स्थिर Eurydice_arr_4d *rhs
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    lhs->तथ्य[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)lhs->तथ्य[i0] *
          (int64_t)rhs->तथ्य[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_montgomery_multiply_65(
  Eurydice_arr_4d *lhs,
  स्थिर Eurydice_arr_4d *rhs
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(lhs, rhs);
}

अटल KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_element(int32_t fe)
{
  int32_t quotient = (fe + (int32_t)((uint32_t)1 << 22U)) >> 23U;
  वापस fe - quotient * LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS;
}

अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(Eurydice_arr_4d *simd_unit)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    simd_unit->तथ्य[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_element(simd_unit->तथ्य[i0]);
  }
}

अटल KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(int32_t t)
{
  int32_t t2 = t + (t >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_FIELD_MODULUS);
  int32_t
  t1 =
    (t2 - 1 +
      (int32_t)((uint32_t)1 <<
        (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T - (माप_प्रकार)1U)))
    >> (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T;
  int32_t
  t0 = t2 - (int32_t)((uint32_t)t1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T);
  वापस (KRML_CLITERAL(int32_t_x2){ .fst = t0, .snd = t1 });
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_arithmetic_power2round(Eurydice_arr_4d *t0, Eurydice_arr_4d *t1)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(t0->तथ्य[i0]);
    int32_t uu____1 = uu____0.snd;
    t0->तथ्य[i0] = uu____0.fst;
    t1->तथ्य[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_power2round_65(Eurydice_arr_4d *t0, Eurydice_arr_4d *t1)
{
  libcrux_ml_dsa_simd_portable_arithmetic_power2round(t0, t1);
}

अटल KRML_MUSTINLINE माप_प्रकार
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_field_modulus(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_83 out
)
{
  माप_प्रकार sampled = (माप_प्रकार)0U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < randomness.meta / (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    int32_t b0 = (int32_t)(uint32_t)randomness.ptr[i0 * (माप_प्रकार)3U];
    int32_t b1 = (int32_t)(uint32_t)randomness.ptr[i0 * (माप_प्रकार)3U + (माप_प्रकार)1U];
    int32_t b2 = (int32_t)(uint32_t)randomness.ptr[i0 * (माप_प्रकार)3U + (माप_प्रकार)2U];
    int32_t
    coefficient = (((int32_t)((uint32_t)b2 << 16U) | (int32_t)((uint32_t)b1 << 8U)) | b0) & 8388607;
    अगर (coefficient < LIBCRUX_ML_DSA_CONSTANTS_FIELD_MODULUS)
    {
      out.ptr[sampled] = coefficient;
      sampled++;
    }
  }
  वापस sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_field_modulus_65(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_83 out
)
{
  वापस
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_field_modulus(randomness,
      out);
}

अटल KRML_MUSTINLINE माप_प्रकार
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_83 out
)
{
  माप_प्रकार sampled = (माप_प्रकार)0U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < randomness.meta; i++)
  {
    माप_प्रकार i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    bool try_0_comp = try_0 < 15U;
    bool try_1_comp = try_1 < 15U;
    अगर (try_0_comp)
    {
      int32_t try_00 = (int32_t)(uint32_t)try_0;
      int32_t try_0_mod_5 = try_00 - (try_00 * 26 >> 7U) * 5;
      out.ptr[sampled] = 2 - try_0_mod_5;
      sampled++;
    }
    अगर (try_1_comp)
    {
      int32_t try_10 = (int32_t)(uint32_t)try_1;
      int32_t try_1_mod_5 = try_10 - (try_10 * 26 >> 7U) * 5;
      out.ptr[sampled] = 2 - try_1_mod_5;
      sampled++;
    }
  }
  वापस sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_83 out
)
{
  वापस
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(randomness,
      out);
}

अटल KRML_MUSTINLINE माप_प्रकार
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_83 out
)
{
  माप_प्रकार sampled = (माप_प्रकार)0U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < randomness.meta; i++)
  {
    माप_प्रकार i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    bool try_0_comp = try_0 < 9U;
    bool try_1_comp = try_1 < 9U;
    अगर (try_0_comp)
    {
      out.ptr[sampled] = 4 - (int32_t)(uint32_t)try_0;
      sampled++;
    }
    अगर (try_1_comp)
    {
      out.ptr[sampled] = 4 - (int32_t)(uint32_t)try_1;
      sampled++;
    }
  }
  वापस sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत माप_प्रकार
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_dst_ref_mut_83 out
)
{
  वापस
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(randomness,
      out);
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)((uint32_t)1 << 19U))

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U / (माप_प्रकार)2U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_to_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)2U,
            .end = i0 * (माप_प्रकार)2U + (माप_प्रकार)2U
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
    serialized.ptr[(माप_प्रकार)5U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(माप_प्रकार)5U * i0 + (माप_प्रकार)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(माप_प्रकार)5U * i0 + (माप_प्रकार)2U] = (uint8_t)(coefficient0 >> 16U);
    माप_प्रकार uu____0 = (माप_प्रकार)5U * i0 + (माप_प्रकार)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 4U);
    serialized.ptr[(माप_प्रकार)5U * i0 + (माप_प्रकार)3U] = (uint8_t)(coefficient1 >> 4U);
    serialized.ptr[(माप_प्रकार)5U * i0 + (माप_प्रकार)4U] = (uint8_t)(coefficient1 >> 12U);
  }
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)((uint32_t)1 << 17U))

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_17(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U / (माप_प्रकार)4U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_to_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)4U,
            .end = i0 * (माप_प्रकार)4U + (माप_प्रकार)4U
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
    serialized.ptr[(माप_प्रकार)9U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(माप_प्रकार)9U * i0 + (माप_प्रकार)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(माप_प्रकार)9U * i0 + (माप_प्रकार)2U] = (uint8_t)(coefficient0 >> 16U);
    माप_प्रकार uu____0 = (माप_प्रकार)9U * i0 + (माप_प्रकार)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 2U);
    serialized.ptr[(माप_प्रकार)9U * i0 + (माप_प्रकार)3U] = (uint8_t)(coefficient1 >> 6U);
    serialized.ptr[(माप_प्रकार)9U * i0 + (माप_प्रकार)4U] = (uint8_t)(coefficient1 >> 14U);
    माप_प्रकार uu____1 = (माप_प्रकार)9U * i0 + (माप_प्रकार)4U;
    serialized.ptr[uu____1] =
      (uint32_t)serialized.ptr[uu____1] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient2 << 4U);
    serialized.ptr[(माप_प्रकार)9U * i0 + (माप_प्रकार)5U] = (uint8_t)(coefficient2 >> 4U);
    serialized.ptr[(माप_प्रकार)9U * i0 + (माप_प्रकार)6U] = (uint8_t)(coefficient2 >> 12U);
    माप_प्रकार uu____2 = (माप_प्रकार)9U * i0 + (माप_प्रकार)6U;
    serialized.ptr[uu____2] =
      (uint32_t)serialized.ptr[uu____2] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient3 << 6U);
    serialized.ptr[(माप_प्रकार)9U * i0 + (माप_प्रकार)7U] = (uint8_t)(coefficient3 >> 2U);
    serialized.ptr[(माप_प्रकार)9U * i0 + (माप_प्रकार)8U] = (uint8_t)(coefficient3 >> 10U);
  }
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized,
  माप_प्रकार gamma1_exponent
)
{
  चयन (gamma1_exponent)
  {
    हाल 17U:
      {
        अवरोध;
      }
    हाल 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(simd_unit,
          serialized);
        वापस;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_17(simd_unit,
    serialized);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_gamma1_serialize_65(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized,
  माप_प्रकार gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(simd_unit, serialized, gamma1_exponent);
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)((uint32_t)1 << 19U))

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK ((int32_t)((uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 << 1U) - 1)

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < serialized.meta / (माप_प्रकार)5U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)5U,
            .end = i0 * (माप_प्रकार)5U + (माप_प्रकार)5U
          }
        ));
    int32_t coefficient0 = (int32_t)(uint32_t)bytes.ptr[0U];
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[1U] << 8U);
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[2U] << 16U);
    coefficient0 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)(uint32_t)bytes.ptr[2U] >> 4U;
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[3U] << 4U);
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[4U] << 12U);
    simd_unit->तथ्य[(माप_प्रकार)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient0;
    simd_unit->तथ्य[(माप_प्रकार)2U * i0 + (माप_प्रकार)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient1;
  }
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)((uint32_t)1 << 17U))

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK ((int32_t)((uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 << 1U) - 1)

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < serialized.meta / (माप_प्रकार)9U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)9U,
            .end = i0 * (माप_प्रकार)9U + (माप_प्रकार)9U
          }
        ));
    int32_t coefficient0 = (int32_t)(uint32_t)bytes.ptr[0U];
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[1U] << 8U);
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[2U] << 16U);
    coefficient0 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)(uint32_t)bytes.ptr[2U] >> 2U;
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[3U] << 6U);
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[4U] << 14U);
    coefficient1 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient2 = (int32_t)(uint32_t)bytes.ptr[4U] >> 4U;
    coefficient2 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[5U] << 4U);
    coefficient2 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[6U] << 12U);
    coefficient2 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient3 = (int32_t)(uint32_t)bytes.ptr[6U] >> 6U;
    coefficient3 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[7U] << 2U);
    coefficient3 |= (int32_t)((uint32_t)(int32_t)(uint32_t)bytes.ptr[8U] << 10U);
    coefficient3 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    simd_unit->तथ्य[(माप_प्रकार)4U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient0;
    simd_unit->तथ्य[(माप_प्रकार)4U * i0 + (माप_प्रकार)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient1;
    simd_unit->तथ्य[(माप_प्रकार)4U * i0 + (माप_प्रकार)2U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient2;
    simd_unit->तथ्य[(माप_प्रकार)4U * i0 + (माप_प्रकार)3U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient3;
  }
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *out,
  माप_प्रकार gamma1_exponent
)
{
  चयन (gamma1_exponent)
  {
    हाल 17U:
      {
        अवरोध;
      }
    हाल 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(serialized,
          out);
        वापस;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(serialized,
    out);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *out,
  माप_प्रकार gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(serialized, out, gamma1_exponent);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->तथ्य[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->तथ्य[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->तथ्य[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->तथ्य[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->तथ्य[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->तथ्य[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->तथ्य[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->तथ्य[7U];
  uint8_t byte0 = (uint32_t)coefficient1 << 4U | (uint32_t)coefficient0;
  uint8_t byte1 = (uint32_t)coefficient3 << 4U | (uint32_t)coefficient2;
  uint8_t byte2 = (uint32_t)coefficient5 << 4U | (uint32_t)coefficient4;
  uint8_t byte3 = (uint32_t)coefficient7 << 4U | (uint32_t)coefficient6;
  serialized.ptr[0U] = byte0;
  serialized.ptr[1U] = byte1;
  serialized.ptr[2U] = byte2;
  serialized.ptr[3U] = byte3;
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->तथ्य[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->तथ्य[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->तथ्य[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->तथ्य[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->तथ्य[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->तथ्य[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->तथ्य[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->तथ्य[7U];
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

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  चयन ((uint32_t)(uint8_t)serialized.meta)
  {
    हाल 4U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(simd_unit, serialized);
        अवरोध;
      }
    हाल 6U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(simd_unit, serialized);
        अवरोध;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_commitment_serialize_65(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(simd_unit, serialized);
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA (4)

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U / (माप_प्रकार)2U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_to_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)2U,
            .end = i0 * (माप_प्रकार)2U + (माप_प्रकार)2U
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

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA (2)

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_2(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  uint8_t
  coefficient0 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->तथ्य[0U]);
  uint8_t
  coefficient1 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->तथ्य[1U]);
  uint8_t
  coefficient2 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->तथ्य[2U]);
  uint8_t
  coefficient3 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->तथ्य[3U]);
  uint8_t
  coefficient4 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->तथ्य[4U]);
  uint8_t
  coefficient5 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->तथ्य[5U]);
  uint8_t
  coefficient6 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->तथ्य[6U]);
  uint8_t
  coefficient7 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->तथ्य[7U]);
  serialized.ptr[0U] =
    ((uint32_t)coefficient2 << 6U | (uint32_t)coefficient1 << 3U) | (uint32_t)coefficient0;
  serialized.ptr[1U] =
    (((uint32_t)coefficient5 << 7U | (uint32_t)coefficient4 << 4U) | (uint32_t)coefficient3 << 1U)
    | (uint32_t)coefficient2 >> 2U;
  serialized.ptr[2U] =
    ((uint32_t)coefficient7 << 5U | (uint32_t)coefficient6 << 2U) | (uint32_t)coefficient5 >> 1U;
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_error_serialize(
  libcrux_ml_dsa_constants_Eta eta,
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  चयन (eta)
  {
    हाल libcrux_ml_dsa_constants_Eta_Two:
      {
        अवरोध;
      }
    हाल libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(simd_unit, serialized);
        वापस;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __खाता__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_2(simd_unit, serialized);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_error_serialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_serialize(eta, simd_unit, serialized);
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA (4)

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *simd_units
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < serialized.meta; i++)
  {
    माप_प्रकार i0 = i;
    स्थिर uint8_t *byte = &serialized.ptr[i0];
    uint8_t uu____0 = core_ops_bit__core__ops__bit__BitAnd_u8__u8__for__0__u8___bitand(byte, 15U);
    simd_units->तथ्य[(माप_प्रकार)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA -
        (int32_t)(uint32_t)uu____0;
    uint8_t uu____1 = core_ops_bit__core__ops__bit__Shr_i32__u8__for__0__u8___shr(byte, 4);
    simd_units->तथ्य[(माप_प्रकार)2U * i0 + (माप_प्रकार)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA -
        (int32_t)(uint32_t)uu____1;
  }
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA (2)

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t byte0 = (int32_t)(uint32_t)serialized.ptr[0U];
  int32_t byte1 = (int32_t)(uint32_t)serialized.ptr[1U];
  int32_t byte2 = (int32_t)(uint32_t)serialized.ptr[2U];
  simd_unit->तथ्य[0U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte0 & 7);
  simd_unit->तथ्य[1U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte0 >> 3U & 7);
  simd_unit->तथ्य[2U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte0 >> 6U | (int32_t)((uint32_t)byte1 << 2U)) & 7);
  simd_unit->तथ्य[3U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte1 >> 1U & 7);
  simd_unit->तथ्य[4U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte1 >> 4U & 7);
  simd_unit->तथ्य[5U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte1 >> 7U | (int32_t)((uint32_t)byte2 << 1U)) & 7);
  simd_unit->तथ्य[6U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte2 >> 2U & 7);
  simd_unit->तथ्य[7U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte2 >> 5U & 7);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_error_deserialize(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *out
)
{
  चयन (eta)
  {
    हाल libcrux_ml_dsa_constants_Eta_Two:
      {
        अवरोध;
      }
    हाल libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(serialized, out);
        वापस;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __खाता__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(serialized, out);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_error_deserialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *out
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize(eta, serialized, out);
}

अटल KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(int32_t t0)
{
  वापस
    (int32_t)((uint32_t)1 <<
      (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T - (माप_प्रकार)1U))
    - t0;
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_t0_serialize(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  int32_t
  coefficient0 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->तथ्य[0U]);
  int32_t
  coefficient1 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->तथ्य[1U]);
  int32_t
  coefficient2 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->तथ्य[2U]);
  int32_t
  coefficient3 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->तथ्य[3U]);
  int32_t
  coefficient4 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->तथ्य[4U]);
  int32_t
  coefficient5 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->तथ्य[5U]);
  int32_t
  coefficient6 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->तथ्य[6U]);
  int32_t
  coefficient7 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->तथ्य[7U]);
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
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_t0_serialize_65(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_serialize(simd_unit, out);
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK ((int32_t)((uint32_t)1 << (uint32_t)(int32_t)LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_LOWER_PART_OF_T) - 1)

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(
  Eurydice_borrow_slice_u8 serialized,
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
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient1 = byte1 >> 5U;
  coefficient1 |= (int32_t)((uint32_t)byte2 << 3U);
  coefficient1 |= (int32_t)((uint32_t)byte3 << 11U);
  coefficient1 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient2 = byte3 >> 2U;
  coefficient2 |= (int32_t)((uint32_t)byte4 << 6U);
  coefficient2 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient3 = byte4 >> 7U;
  coefficient3 |= (int32_t)((uint32_t)byte5 << 1U);
  coefficient3 |= (int32_t)((uint32_t)byte6 << 9U);
  coefficient3 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient4 = byte6 >> 4U;
  coefficient4 |= (int32_t)((uint32_t)byte7 << 4U);
  coefficient4 |= (int32_t)((uint32_t)byte8 << 12U);
  coefficient4 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient5 = byte8 >> 1U;
  coefficient5 |= (int32_t)((uint32_t)byte9 << 7U);
  coefficient5 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient6 = byte9 >> 6U;
  coefficient6 |= (int32_t)((uint32_t)byte10 << 2U);
  coefficient6 |= (int32_t)((uint32_t)byte11 << 10U);
  coefficient6 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  int32_t coefficient7 = byte11 >> 3U;
  coefficient7 |= (int32_t)((uint32_t)byte12 << 5U);
  coefficient7 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_BITS_IN_LOWER_PART_OF_T_MASK;
  simd_unit->तथ्य[0U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient0);
  simd_unit->तथ्य[1U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient1);
  simd_unit->तथ्य[2U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient2);
  simd_unit->तथ्य[3U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient3);
  simd_unit->तथ्य[4U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient4);
  simd_unit->तथ्य[5U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient5);
  simd_unit->तथ्य[6U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient6);
  simd_unit->तथ्य[7U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient7);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_t0_deserialize_65(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *out
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(serialized, out);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_t1_serialize(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U / (माप_प्रकार)4U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_to_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)4U,
            .end = i0 * (माप_प्रकार)4U + (माप_प्रकार)4U
          }
        ));
    serialized.ptr[(माप_प्रकार)5U * i0] = (uint8_t)(coefficients.ptr[0U] & 255);
    serialized.ptr[(माप_प्रकार)5U * i0 + (माप_प्रकार)1U] =
      (uint32_t)(uint8_t)(coefficients.ptr[1U] & 63) << 2U |
        (uint32_t)(uint8_t)(coefficients.ptr[0U] >> 8U & 3);
    serialized.ptr[(माप_प्रकार)5U * i0 + (माप_प्रकार)2U] =
      (uint32_t)(uint8_t)(coefficients.ptr[2U] & 15) << 4U |
        (uint32_t)(uint8_t)(coefficients.ptr[1U] >> 6U & 15);
    serialized.ptr[(माप_प्रकार)5U * i0 + (माप_प्रकार)3U] =
      (uint32_t)(uint8_t)(coefficients.ptr[3U] & 3) << 6U |
        (uint32_t)(uint8_t)(coefficients.ptr[2U] >> 4U & 63);
    serialized.ptr[(माप_प्रकार)5U * i0 + (माप_प्रकार)4U] = (uint8_t)(coefficients.ptr[3U] >> 2U & 255);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_t1_serialize_65(
  स्थिर Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_serialize(simd_unit, out);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t
  mask = (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_BITS_IN_UPPER_PART_OF_T) - 1;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < serialized.meta / (माप_प्रकार)5U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)5U,
            .end = i0 * (माप_प्रकार)5U + (माप_प्रकार)5U
          }
        ));
    int32_t byte0 = (int32_t)(uint32_t)bytes.ptr[0U];
    int32_t byte1 = (int32_t)(uint32_t)bytes.ptr[1U];
    int32_t byte2 = (int32_t)(uint32_t)bytes.ptr[2U];
    int32_t byte3 = (int32_t)(uint32_t)bytes.ptr[3U];
    int32_t byte4 = (int32_t)(uint32_t)bytes.ptr[4U];
    simd_unit->तथ्य[(माप_प्रकार)4U * i0] = (byte0 | (int32_t)((uint32_t)byte1 << 8U)) & mask;
    simd_unit->तथ्य[(माप_प्रकार)4U * i0 + (माप_प्रकार)1U] =
      (byte1 >> 2U | (int32_t)((uint32_t)byte2 << 6U)) & mask;
    simd_unit->तथ्य[(माप_प्रकार)4U * i0 + (माप_प्रकार)2U] =
      (byte2 >> 4U | (int32_t)((uint32_t)byte3 << 4U)) & mask;
    simd_unit->तथ्य[(माप_प्रकार)4U * i0 + (माप_प्रकार)3U] =
      (byte3 >> 6U | (int32_t)((uint32_t)byte4 << 2U)) & mask;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_t1_deserialize_65(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_4d *out
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(serialized, out);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_4d *simd_unit,
  int32_t c
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    simd_unit->तथ्य[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)simd_unit->तथ्य[i0]
        * (int64_t)c);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- $32size_t
*/
प्रकार काष्ठा Eurydice_arr_a3_s { Eurydice_arr_4d तथ्य[32U]; } Eurydice_arr_a3;

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(
  Eurydice_arr_a3 *re,
  माप_प्रकार index,
  माप_प्रकार step_by,
  int32_t zeta
)
{
  Eurydice_arr_4d tmp = re->तथ्य[index + step_by];
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&tmp, zeta);
  re->तथ्य[index + step_by] = re->तथ्य[index];
  libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[index + step_by], &tmp);
  libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[index], &tmp);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 16
- ZETA= 25847
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_30(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)16U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)16U, 25847);
  }
}

अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_300(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)8U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)8U, -2608894);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 8
- ZETA= -518909
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_42(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)16U; i < (माप_प्रकार)16U + (माप_प्रकार)8U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)8U, -518909);
  }
}

अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_301(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)4U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)4U, 237124);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 4
- ZETA= -777960
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_82(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)8U; i < (माप_प्रकार)8U + (माप_प्रकार)4U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)4U, -777960);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 4
- ZETA= -876248
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_420(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)16U; i < (माप_प्रकार)16U + (माप_प्रकार)4U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)4U, -876248);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 4
- ZETA= 466468
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)24U; i < (माप_प्रकार)24U + (माप_प्रकार)4U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)4U, 466468);
  }
}

अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_302(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)2U, 1826347);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 2
- ZETA= 2353451
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_43(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)4U; i < (माप_प्रकार)4U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)2U, 2353451);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 2
- ZETA= -359251
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_820(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)8U; i < (माप_प्रकार)8U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)2U, -359251);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 2
- ZETA= -2091905
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)12U; i < (माप_प्रकार)12U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)2U, -2091905);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 2
- ZETA= 3119733
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_421(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)16U; i < (माप_प्रकार)16U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)2U, 3119733);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 2
- ZETA= -2884855
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_61(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)20U; i < (माप_प्रकार)20U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)2U, -2884855);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 2
- ZETA= 3111497
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe0(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)24U; i < (माप_प्रकार)24U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)2U, 3111497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 2
- ZETA= 2680103
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_38(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)28U; i < (माप_प्रकार)28U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)2U, 2680103);
  }
}

अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_303(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, 2725464);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 2
- STEP_BY= 1
- ZETA= 1024112
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_25(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)2U; i < (माप_प्रकार)2U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, 1024112);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 1
- ZETA= -1079900
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_430(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)4U; i < (माप_प्रकार)4U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, -1079900);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 6
- STEP_BY= 1
- ZETA= 3585928
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_f4(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)6U; i < (माप_प्रकार)6U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, 3585928);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 1
- ZETA= -549488
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_821(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)8U; i < (माप_प्रकार)8U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, -549488);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 10
- STEP_BY= 1
- ZETA= -1119584
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1d(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)10U; i < (माप_प्रकार)10U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, -1119584);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 1
- ZETA= 2619752
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea0(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)12U; i < (माप_प्रकार)12U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, 2619752);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 14
- STEP_BY= 1
- ZETA= -2108549
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d8(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)14U; i < (माप_प्रकार)14U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, -2108549);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 1
- ZETA= -2118186
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_422(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)16U; i < (माप_प्रकार)16U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, -2118186);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 18
- STEP_BY= 1
- ZETA= -3859737
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_60(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)18U; i < (माप_प्रकार)18U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, -3859737);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 1
- ZETA= -1399561
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_610(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)20U; i < (माप_प्रकार)20U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, -1399561);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 22
- STEP_BY= 1
- ZETA= -3277672
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_29(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)22U; i < (माप_प्रकार)22U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, -3277672);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 1
- ZETA= 1757237
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe1(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)24U; i < (माप_प्रकार)24U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, 1757237);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 26
- STEP_BY= 1
- ZETA= -19422
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_9d(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)26U; i < (माप_प्रकार)26U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, -19422);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 1
- ZETA= 4010497
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_380(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)28U; i < (माप_प्रकार)28U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, 4010497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 30
- STEP_BY= 1
- ZETA= 280005
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_5f(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)30U; i < (माप_प्रकार)30U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_round(re, j, (माप_प्रकार)1U, 280005);
  }
}

अटल KRML_MUSTINLINE व्योम
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

अटल KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(int32_t fe, int32_t fer)
{
  वापस
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)fe * (int64_t)fer);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta,
  माप_प्रकार index,
  माप_प्रकार step
)
{
  int32_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(simd_unit->तथ्य[index +
        step],
      zeta);
  simd_unit->तथ्य[index + step] = simd_unit->तथ्य[index] - t;
  simd_unit->तथ्य[index] += t;
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta, (माप_प्रकार)0U, (माप_प्रकार)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta, (माप_प्रकार)1U, (माप_प्रकार)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta, (माप_प्रकार)2U, (माप_प्रकार)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta, (माप_प्रकार)3U, (माप_प्रकार)4U);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(
  Eurydice_arr_a3 *re,
  माप_प्रकार index,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(&re->तथ्य[index], zeta);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)0U, 2706023);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)1U, 95776);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)2U, 3077325);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)3U, 3530437);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)4U, -1661693);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)5U, -3592148);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)6U, -2537516);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)7U, 3915439);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)8U, -3861115);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)9U, -3043716);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)10U, 3574422);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)11U, -2867647);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)12U, 3539968);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)13U, -300467);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)14U, 2348700);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)15U, -539299);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)16U, -1699267);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)17U, -1643818);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)18U, 3505694);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)19U, -3821735);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)20U, 3507263);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)21U, -2140649);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)22U, -1600420);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)23U, 3699596);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)24U, 811944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)25U, 531354);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)26U, 954230);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)27U, 3881043);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)28U, 3900724);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)29U, -2556880);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)30U, 2071892);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_round(re, (माप_प्रकार)31U, -2797779);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta1,
  int32_t zeta2
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta1, (माप_प्रकार)0U, (माप_प्रकार)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta1, (माप_प्रकार)1U, (माप_प्रकार)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta2, (माप_प्रकार)4U, (माप_प्रकार)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta2, (माप_प्रकार)5U, (माप_प्रकार)2U);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(
  Eurydice_arr_a3 *re,
  माप_प्रकार index,
  int32_t zeta_0,
  int32_t zeta_1
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(&re->तथ्य[index], zeta_0, zeta_1);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)0U, -3930395, -1528703);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)1U, -3677745, -3041255);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)2U, -1452451, 3475950);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)3U, 2176455, -1585221);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)4U, -1257611, 1939314);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)5U, -4083598, -1000202);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)6U, -3190144, -3157330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)7U, -3632928, 126922);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)8U, 3412210, -983419);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)9U, 2147896, 2715295);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)10U, -2967645, -3693493);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)11U, -411027, -2477047);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)12U, -671102, -1228525);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)13U, -22981, -1308169);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)14U, -381987, 1349076);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)15U, 1852771, -1430430);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)16U, -3343383, 264944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)17U, 508951, 3097992);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)18U, 44288, -1100098);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)19U, 904516, 3958618);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)20U, -3724342, -8578);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)21U, 1653064, -3249728);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)22U, 2389356, -210977);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)23U, 759969, -1316856);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)24U, 189548, -3553272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)25U, 3159746, -1851402);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)26U, -2409325, -177440);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)27U, 1315589, 1341330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)28U, 1285669, -1584928);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)29U, -812732, -1439742);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)30U, -3019102, -3881060);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_round(re, (माप_प्रकार)31U, -3628969, 3839961);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta0, (माप_प्रकार)0U, (माप_प्रकार)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta1, (माप_प्रकार)2U, (माप_प्रकार)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta2, (माप_प्रकार)4U, (माप_प्रकार)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_step(simd_unit, zeta3, (माप_प्रकार)6U, (माप_प्रकार)1U);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(
  Eurydice_arr_a3 *re,
  माप_प्रकार index,
  int32_t zeta_0,
  int32_t zeta_1,
  int32_t zeta_2,
  int32_t zeta_3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(&re->तथ्य[index],
    zeta_0,
    zeta_1,
    zeta_2,
    zeta_3);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)0U,
    2091667,
    3407706,
    2316500,
    3817976);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)1U,
    -3342478,
    2244091,
    -2446433,
    -3562462);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)2U,
    266997,
    2434439,
    -1235728,
    3513181);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)3U,
    -3520352,
    -3759364,
    -1197226,
    -3193378);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)4U,
    900702,
    1859098,
    909542,
    819034);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)5U,
    495491,
    -1613174,
    -43260,
    -522500);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)6U,
    -655327,
    -3122442,
    2031748,
    3207046);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)7U,
    -3556995,
    -525098,
    -768622,
    -3595838);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)8U,
    342297,
    286988,
    -2437823,
    4108315);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)9U,
    3437287,
    -3342277,
    1735879,
    203044);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)10U,
    2842341,
    2691481,
    -2590150,
    1265009);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)11U,
    4055324,
    1247620,
    2486353,
    1595974);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)12U,
    -3767016,
    1250494,
    2635921,
    -3548272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)13U,
    -2994039,
    1869119,
    1903435,
    -1050970);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)14U,
    -1333058,
    1237275,
    -3318210,
    -1430225);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)15U,
    -451100,
    1312455,
    3306115,
    -1962642);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)16U,
    -1279661,
    1917081,
    -2546312,
    -1374803);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)17U,
    1500165,
    777191,
    2235880,
    3406031);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)18U,
    -542412,
    -2831860,
    -1671176,
    -1846953);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)19U,
    -2584293,
    -3724270,
    594136,
    -3776993);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)20U,
    -2013608,
    2432395,
    2454455,
    -164721);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)21U,
    1957272,
    3369112,
    185531,
    -1207385);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)22U,
    -3183426,
    162844,
    1616392,
    3014001);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)23U,
    810149,
    1652634,
    -3694233,
    -1799107);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)24U,
    -3038916,
    3523897,
    3866901,
    269760);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)25U,
    2213111,
    -975884,
    1717735,
    472078);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)26U,
    -426683,
    1723600,
    -1803090,
    1910376);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)27U,
    -1667432,
    -1104333,
    -260646,
    -3833893);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)28U,
    -2939036,
    -2235985,
    -420899,
    -2286327);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)29U,
    183443,
    -976891,
    1612842,
    -3545687);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)30U,
    -554416,
    3919660,
    -48306,
    -1362209);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_round(re,
    (माप_प्रकार)31U,
    3937738,
    1400424,
    -846154,
    1976782);
}

अटल KRML_MUSTINLINE व्योम libcrux_ml_dsa_simd_portable_ntt_ntt(Eurydice_arr_a3 *re)
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
अटल अंतरभूत व्योम libcrux_ml_dsa_simd_portable_ntt_65(Eurydice_arr_a3 *simd_units)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt(simd_units);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta,
  माप_प्रकार index,
  माप_प्रकार step
)
{
  int32_t a_minus_b = simd_unit->तथ्य[index + step] - simd_unit->तथ्य[index];
  simd_unit->तथ्य[index] += simd_unit->तथ्य[index + step];
  simd_unit->तथ्य[index + step] =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      zeta);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta0,
    (माप_प्रकार)0U,
    (माप_प्रकार)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta1,
    (माप_प्रकार)2U,
    (माप_प्रकार)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta2,
    (माप_प्रकार)4U,
    (माप_प्रकार)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta3,
    (माप_प्रकार)6U,
    (माप_प्रकार)1U);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(
  Eurydice_arr_a3 *re,
  माप_प्रकार index,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(&re->तथ्य[index],
    zeta0,
    zeta1,
    zeta2,
    zeta3);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)0U,
    1976782,
    -846154,
    1400424,
    3937738);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)1U,
    -1362209,
    -48306,
    3919660,
    -554416);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)2U,
    -3545687,
    1612842,
    -976891,
    183443);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)3U,
    -2286327,
    -420899,
    -2235985,
    -2939036);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)4U,
    -3833893,
    -260646,
    -1104333,
    -1667432);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)5U,
    1910376,
    -1803090,
    1723600,
    -426683);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)6U,
    472078,
    1717735,
    -975884,
    2213111);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)7U,
    269760,
    3866901,
    3523897,
    -3038916);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)8U,
    -1799107,
    -3694233,
    1652634,
    810149);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)9U,
    3014001,
    1616392,
    162844,
    -3183426);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)10U,
    -1207385,
    185531,
    3369112,
    1957272);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)11U,
    -164721,
    2454455,
    2432395,
    -2013608);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)12U,
    -3776993,
    594136,
    -3724270,
    -2584293);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)13U,
    -1846953,
    -1671176,
    -2831860,
    -542412);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)14U,
    3406031,
    2235880,
    777191,
    1500165);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)15U,
    -1374803,
    -2546312,
    1917081,
    -1279661);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)16U,
    -1962642,
    3306115,
    1312455,
    -451100);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)17U,
    -1430225,
    -3318210,
    1237275,
    -1333058);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)18U,
    -1050970,
    1903435,
    1869119,
    -2994039);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)19U,
    -3548272,
    2635921,
    1250494,
    -3767016);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)20U,
    1595974,
    2486353,
    1247620,
    4055324);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)21U,
    1265009,
    -2590150,
    2691481,
    2842341);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)22U,
    203044,
    1735879,
    -3342277,
    3437287);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)23U,
    4108315,
    -2437823,
    286988,
    342297);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)24U,
    -3595838,
    -768622,
    -525098,
    -3556995);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)25U,
    3207046,
    2031748,
    -3122442,
    -655327);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)26U,
    -522500,
    -43260,
    -1613174,
    495491);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)27U,
    819034,
    909542,
    1859098,
    900702);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)28U,
    -3193378,
    -1197226,
    -3759364,
    -3520352);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)29U,
    3513181,
    -1235728,
    2434439,
    266997);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)30U,
    -3562462,
    -2446433,
    2244091,
    -3342478);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_round(re,
    (माप_प्रकार)31U,
    3817976,
    2316500,
    3407706,
    2091667);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta0,
    (माप_प्रकार)0U,
    (माप_प्रकार)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta0,
    (माप_प्रकार)1U,
    (माप_प्रकार)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta1,
    (माप_प्रकार)4U,
    (माप_प्रकार)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta1,
    (माप_प्रकार)5U,
    (माप_प्रकार)2U);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(
  Eurydice_arr_a3 *re,
  माप_प्रकार index,
  int32_t zeta_00,
  int32_t zeta_01
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(&re->तथ्य[index],
    zeta_00,
    zeta_01);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)0U,
    3839961,
    -3628969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)1U,
    -3881060,
    -3019102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)2U,
    -1439742,
    -812732);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)3U,
    -1584928,
    1285669);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)4U,
    1341330,
    1315589);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)5U,
    -177440,
    -2409325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)6U,
    -1851402,
    3159746);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)7U,
    -3553272,
    189548);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)8U,
    -1316856,
    759969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)9U,
    -210977,
    2389356);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)10U,
    -3249728,
    1653064);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)11U,
    -8578,
    -3724342);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)12U,
    3958618,
    904516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)13U,
    -1100098,
    44288);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)14U,
    3097992,
    508951);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)15U,
    264944,
    -3343383);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)16U,
    -1430430,
    1852771);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)17U,
    1349076,
    -381987);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)18U,
    -1308169,
    -22981);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)19U,
    -1228525,
    -671102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)20U,
    -2477047,
    -411027);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)21U,
    -3693493,
    -2967645);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)22U,
    2715295,
    2147896);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)23U,
    -983419,
    3412210);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)24U,
    126922,
    -3632928);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)25U,
    -3157330,
    -3190144);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)26U,
    -1000202,
    -4083598);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)27U,
    1939314,
    -1257611);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)28U,
    -1585221,
    2176455);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)29U,
    3475950,
    -1452451);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)30U,
    -3041255,
    -3677745);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_round(re,
    (माप_प्रकार)31U,
    -1528703,
    -3930395);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta,
    (माप_प्रकार)0U,
    (माप_प्रकार)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta,
    (माप_प्रकार)1U,
    (माप_प्रकार)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta,
    (माप_प्रकार)2U,
    (माप_प्रकार)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_step(simd_unit,
    zeta,
    (माप_प्रकार)3U,
    (माप_प्रकार)4U);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(
  Eurydice_arr_a3 *re,
  माप_प्रकार index,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(&re->तथ्य[index], zeta1);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)0U, -2797779);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)1U, 2071892);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)2U, -2556880);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)3U, 3900724);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)4U, 3881043);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)5U, 954230);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)6U, 531354);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)7U, 811944);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)8U, 3699596);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)9U, -1600420);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)10U, -2140649);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)11U, 3507263);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)12U, -3821735);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)13U, 3505694);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)14U, -1643818);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)15U, -1699267);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)16U, -539299);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)17U, 2348700);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)18U, -300467);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)19U, 3539968);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)20U, -2867647);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)21U, 3574422);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)22U, -3043716);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)23U, -3861115);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)24U, 3915439);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)25U, -2537516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)26U, -3592148);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)27U, -1661693);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)28U, 3530437);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)29U, 3077325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)30U, 95776);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_round(re, (माप_प्रकार)31U, 2706023);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 1
- ZETA= 280005
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_30(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_25(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)2U; i < (माप_प्रकार)2U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_43(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)4U; i < (माप_प्रकार)4U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_f4(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)6U; i < (माप_प्रकार)6U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_82(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)8U; i < (माप_प्रकार)8U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1d(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)10U; i < (माप_प्रकार)10U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)12U; i < (माप_प्रकार)12U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d8(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)14U; i < (माप_प्रकार)14U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_42(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)16U; i < (माप_प्रकार)16U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_60(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)18U; i < (माप_प्रकार)18U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_61(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)20U; i < (माप_प्रकार)20U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_29(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)22U; i < (माप_प्रकार)22U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)24U; i < (माप_प्रकार)24U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_9d(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)26U; i < (माप_प्रकार)26U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_38(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)28U; i < (माप_प्रकार)28U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_5f(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)30U; i < (माप_प्रकार)30U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)1U],
      2725464);
  }
}

अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_300(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)2U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_430(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)4U; i < (माप_प्रकार)4U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)2U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_820(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)8U; i < (माप_प्रकार)8U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)2U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea0(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)12U; i < (माप_प्रकार)12U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)2U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_420(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)16U; i < (माप_प्रकार)16U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)2U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_610(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)20U; i < (माप_प्रकार)20U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)2U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe0(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)24U; i < (माप_प्रकार)24U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)2U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_380(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)28U; i < (माप_प्रकार)28U + (माप_प्रकार)2U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)2U],
      1826347);
  }
}

अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_301(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)4U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)4U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_821(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)8U; i < (माप_प्रकार)8U + (माप_प्रकार)4U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)4U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_421(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)16U; i < (माप_प्रकार)16U + (माप_प्रकार)4U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)4U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe1(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)24U; i < (माप_प्रकार)24U + (माप_प्रकार)4U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)4U],
      237124);
  }
}

अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_302(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)8U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)8U],
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_422(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)16U; i < (माप_प्रकार)16U + (माप_प्रकार)8U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)8U],
      -2608894);
  }
}

अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_303(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)0U + (माप_प्रकार)16U; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_4d rej = re->तथ्य[j];
    Eurydice_arr_4d rejs = re->तथ्य[j + (माप_प्रकार)16U];
    libcrux_ml_dsa_simd_portable_arithmetic_add(&re->तथ्य[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_subtract(&re->तथ्य[j + (माप_प्रकार)16U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[j +
        (माप_प्रकार)16U],
      25847);
  }
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_7(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_303(re);
}

अटल KRML_MUSTINLINE व्योम
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
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->तथ्य[i0], 41978);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_invert_ntt_montgomery_65(Eurydice_arr_a3 *simd_units)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_montgomery(simd_units);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_barrett_reduce_simd_unit_65(Eurydice_arr_4d *simd_unit)
{
  libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(simd_unit);
}

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_आकार (libcrux_ml_dsa_constants_error_ring_element_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_ERROR_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_आकार (libcrux_ml_dsa_constants_commitment_ring_element_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_COMMITMENT_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_IN_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_आकार (libcrux_ml_dsa_constants_gamma1_ring_element_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_GAMMA1_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_कुंजी_आकार (libcrux_ml_dsa_constants_verification_कुंजी_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_आकार (libcrux_ml_dsa_constants_signature_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_आकार, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_GAMMA1_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_आकार (libcrux_ml_dsa_constants_error_ring_element_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_BITS_PER_ERROR_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_आकार (libcrux_ml_dsa_constants_commitment_ring_element_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_BITS_PER_COMMITMENT_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_IN_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_आकार (libcrux_ml_dsa_constants_gamma1_ring_element_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_BITS_PER_GAMMA1_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_VERIFICATION_कुंजी_आकार (libcrux_ml_dsa_constants_verification_कुंजी_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNATURE_आकार (libcrux_ml_dsa_constants_signature_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_IN_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_आकार, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_BITS_PER_GAMMA1_COEFFICIENT))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_VECTOR_आकार (libcrux_ml_dsa_constants_commitment_vector_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_BITS_PER_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $2560size_t
*/
प्रकार Eurydice_arr_10 libcrux_ml_dsa_types_MLDSASigning_कुंजी_11;

प्रकार Eurydice_arr_10 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_Signing_कुंजी;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $1312size_t
*/
प्रकार Eurydice_arr_02 libcrux_ml_dsa_types_MLDSAVerification_कुंजी_1d;

प्रकार Eurydice_arr_02 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_Verification_कुंजी;

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ROW_COLUMN (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A)

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ROW_X_COLUMN (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A)

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNING_कुंजी_आकार (libcrux_ml_dsa_constants_signing_कुंजी_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_आकार))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_VECTOR_आकार (libcrux_ml_dsa_constants_commitment_vector_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_BITS_PER_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $4032size_t
*/
प्रकार Eurydice_arr_24 libcrux_ml_dsa_types_MLDSASigning_कुंजी_8e;

प्रकार Eurydice_arr_24 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_Signing_कुंजी;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $1952size_t
*/
प्रकार Eurydice_arr_29 libcrux_ml_dsa_types_MLDSAVerification_कुंजी_c8;

प्रकार Eurydice_arr_29 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_Verification_कुंजी;

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ROW_COLUMN (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A)

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ROW_X_COLUMN (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A)

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNING_कुंजी_आकार (libcrux_ml_dsa_constants_signing_कुंजी_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_आकार))

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_VECTOR_आकार (libcrux_ml_dsa_constants_commitment_vector_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_BITS_PER_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $4896size_t
*/
प्रकार Eurydice_arr_e2 libcrux_ml_dsa_types_MLDSASigning_कुंजी_b8;

प्रकार Eurydice_arr_e2 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_Signing_कुंजी;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $2592size_t
*/
प्रकार Eurydice_arr_43 libcrux_ml_dsa_types_MLDSAVerification_कुंजी_e9;

प्रकार Eurydice_arr_43 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_Verification_कुंजी;

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ROW_COLUMN (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A)

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ROW_X_COLUMN (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A)

#घोषणा LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNING_कुंजी_आकार (libcrux_ml_dsa_constants_signing_कुंजी_आकार(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_आकार))

#घोषणा LIBCRUX_ML_DSA_PRE_HASH_PRE_HASH_OID_LEN ((माप_प्रकार)11U)

प्रकार Eurydice_arr_c9 libcrux_ml_dsa_pre_hash_PreHashOID;

प्रकार core_परिणाम_परिणाम_a8 libcrux_ml_dsa_pre_hash_Pre_Hash_परिणाम;

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::SigningError}
*/
अटल अंतरभूत libcrux_ml_dsa_types_SigningError
libcrux_ml_dsa_pre_hash_from_96(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  वापस libcrux_ml_dsa_types_SigningError_ContextTooLongError;
}

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::VerificationError}
*/
अटल अंतरभूत libcrux_ml_dsa_types_VerificationError
libcrux_ml_dsa_pre_hash_from_bf(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  वापस libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError;
}

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_3_STEP ((माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_3_STEP_BY ((माप_प्रकार)1U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_4_STEP ((माप_प्रकार)16U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_4_STEP_BY ((माप_प्रकार)2U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_5_STEP ((माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_5_STEP_BY ((माप_प्रकार)4U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_6_STEP ((माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_6_STEP_BY ((माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_7_STEP ((माप_प्रकार)128U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_7_STEP_BY ((माप_प्रकार)16U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_3_STEP ((माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_3_STEP_BY ((माप_प्रकार)1U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_4_STEP ((माप_प्रकार)16U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_4_STEP_BY ((माप_प्रकार)2U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_5_STEP ((माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_5_STEP_BY ((माप_प्रकार)4U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_6_STEP ((माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_6_STEP_BY ((माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_7_STEP ((माप_प्रकार)128U)

#घोषणा LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_7_STEP_BY ((माप_प्रकार)16U)

प्रकार int32_t libcrux_ml_dsa_simd_portable_vector_type_FieldElement;

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
अटल अंतरभूत Eurydice_arr_4d
libcrux_ml_dsa_simd_portable_vector_type_clone_a5(स्थिर Eurydice_arr_4d *self)
{
  वापस self[0U];
}

प्रकार int32_t libcrux_ml_dsa_simd_traits_FieldElementTimesMontgomeryR;

प्रकार Eurydice_arr_93 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87Signature;

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
अटल अंतरभूत स्थिर
Eurydice_arr_93
*libcrux_ml_dsa_types_as_ref_c5_f1(स्थिर Eurydice_arr_93 *self)
{
  वापस self;
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
अटल अंतरभूत स्थिर
Eurydice_arr_43
*libcrux_ml_dsa_types_as_ref_7f_c6(स्थिर Eurydice_arr_43 *self)
{
  वापस self;
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
अटल अंतरभूत स्थिर
Eurydice_arr_e2
*libcrux_ml_dsa_types_as_ref_9b_72(स्थिर Eurydice_arr_e2 *self)
{
  वापस self;
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
अटल अंतरभूत Eurydice_arr_43 libcrux_ml_dsa_types_new_7f_c6(Eurydice_arr_43 मूल्य)
{
  वापस मूल्य;
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
अटल अंतरभूत Eurydice_arr_e2 libcrux_ml_dsa_types_new_9b_72(Eurydice_arr_e2 मूल्य)
{
  वापस मूल्य;
}

प्रकार Eurydice_arr_85 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44Signature;

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
अटल अंतरभूत स्थिर
Eurydice_arr_85
*libcrux_ml_dsa_types_as_ref_c5_37(स्थिर Eurydice_arr_85 *self)
{
  वापस self;
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
अटल अंतरभूत स्थिर
Eurydice_arr_02
*libcrux_ml_dsa_types_as_ref_7f_7d(स्थिर Eurydice_arr_02 *self)
{
  वापस self;
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
अटल अंतरभूत स्थिर
Eurydice_arr_10
*libcrux_ml_dsa_types_as_ref_9b_ab(स्थिर Eurydice_arr_10 *self)
{
  वापस self;
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
अटल अंतरभूत Eurydice_arr_02 libcrux_ml_dsa_types_new_7f_7d(Eurydice_arr_02 मूल्य)
{
  वापस मूल्य;
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
अटल अंतरभूत Eurydice_arr_10 libcrux_ml_dsa_types_new_9b_ab(Eurydice_arr_10 मूल्य)
{
  वापस मूल्य;
}

प्रकार Eurydice_arr_0c libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65Signature;

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
अटल अंतरभूत स्थिर
Eurydice_arr_0c
*libcrux_ml_dsa_types_as_ref_c5_5c(स्थिर Eurydice_arr_0c *self)
{
  वापस self;
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
अटल अंतरभूत स्थिर
Eurydice_arr_29
*libcrux_ml_dsa_types_as_ref_7f_a2(स्थिर Eurydice_arr_29 *self)
{
  वापस self;
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
अटल अंतरभूत स्थिर
Eurydice_arr_24
*libcrux_ml_dsa_types_as_ref_9b_e5(स्थिर Eurydice_arr_24 *self)
{
  वापस self;
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
अटल अंतरभूत Eurydice_arr_29 libcrux_ml_dsa_types_new_7f_a2(Eurydice_arr_29 मूल्य)
{
  वापस मूल्य;
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
अटल अंतरभूत Eurydice_arr_24 libcrux_ml_dsa_types_new_9b_e5(Eurydice_arr_24 मूल्य)
{
  वापस मूल्य;
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87Signature, libcrux_ml_dsa_types_SigningError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_8b_s
{
  core_परिणाम_परिणाम_57_tags tag;
  जोड़ {
    Eurydice_arr_93 case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_परिणाम_परिणाम_8b;

/**
A monomorphic instance of libcrux_ml_dsa.polynomial.PolynomialRingElement
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients

*/
प्रकार Eurydice_arr_a3 libcrux_ml_dsa_polynomial_PolynomialRingElement_e8;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $7size_t
*/
प्रकार काष्ठा Eurydice_arr_bb_s { Eurydice_arr_a3 तथ्य[7U]; } Eurydice_arr_bb;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_bb

*/
प्रकार काष्ठा core_option_Option_2d_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_bb f0;
}
core_option_Option_2d;

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
प्रकार काष्ठा Eurydice_dst_ref_shared_44_s
{
  स्थिर Eurydice_arr_a3 *ptr;
  माप_प्रकार meta;
}
Eurydice_dst_ref_shared_44;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $56size_t
*/
प्रकार काष्ठा Eurydice_arr_0f_s { Eurydice_arr_a3 तथ्य[56U]; } Eurydice_arr_0f;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 56
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_208(स्थिर Eurydice_arr_0f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)56U;
  वापस lit;
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
अटल अंतरभूत Eurydice_arr_93 libcrux_ml_dsa_types_zero_c5_f1(व्योम)
{
  वापस (KRML_CLITERAL(Eurydice_arr_93){ .तथ्य = { 0U } });
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $8size_t
*/
प्रकार काष्ठा Eurydice_arr_8f_s { Eurydice_arr_a3 तथ्य[8U]; } Eurydice_arr_8f;

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$8size_t]]

*/
अटल KRML_MUSTINLINE व्योम
libcrux_secrets_mem_requests_ct_declassify_6a(स्थिर Eurydice_arr_8f *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $15size_t
*/
प्रकार काष्ठा Eurydice_arr_92_s { Eurydice_arr_a3 तथ्य[15U]; } Eurydice_arr_92;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_207(स्थिर Eurydice_arr_92 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)15U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 7
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_206(स्थिर Eurydice_arr_bb *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)7U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_subslice_shared_251(स्थिर Eurydice_arr_92 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start }
    );
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
प्रकार काष्ठा Eurydice_dst_ref_mut_44_s
{
  Eurydice_arr_a3 *ptr;
  माप_प्रकार meta;
}
Eurydice_dst_ref_mut_44;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 7
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_208(Eurydice_arr_bb *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)7U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 56
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_207(Eurydice_arr_0f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)56U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_206(Eurydice_arr_92 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)15U;
  वापस lit;
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65Signature, libcrux_ml_dsa_types_SigningError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_8c_s
{
  core_परिणाम_परिणाम_57_tags tag;
  जोड़ {
    Eurydice_arr_0c case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_परिणाम_परिणाम_8c;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $5size_t
*/
प्रकार काष्ठा Eurydice_arr_5d_s { Eurydice_arr_a3 तथ्य[5U]; } Eurydice_arr_5d;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_5d

*/
प्रकार काष्ठा core_option_Option_1e_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_5d f0;
}
core_option_Option_1e;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $30size_t
*/
प्रकार काष्ठा Eurydice_arr_5a_s { Eurydice_arr_a3 तथ्य[30U]; } Eurydice_arr_5a;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_205(स्थिर Eurydice_arr_5a *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)30U;
  वापस lit;
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
अटल अंतरभूत Eurydice_arr_0c libcrux_ml_dsa_types_zero_c5_5c(व्योम)
{
  वापस (KRML_CLITERAL(Eurydice_arr_0c){ .तथ्य = { 0U } });
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $6size_t
*/
प्रकार काष्ठा Eurydice_arr_dc1_s { Eurydice_arr_a3 तथ्य[6U]; } Eurydice_arr_dc1;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_204(स्थिर Eurydice_arr_dc1 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)6U;
  वापस lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$6size_t]]

*/
अटल KRML_MUSTINLINE व्योम
libcrux_secrets_mem_requests_ct_declassify_b2(स्थिर Eurydice_arr_dc1 *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_205(Eurydice_arr_dc1 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)6U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $11size_t
*/
प्रकार काष्ठा Eurydice_arr_47_s { Eurydice_arr_a3 तथ्य[11U]; } Eurydice_arr_47;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_203(स्थिर Eurydice_arr_47 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)11U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_202(स्थिर Eurydice_arr_5d *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)5U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_subslice_shared_250(स्थिर Eurydice_arr_47 *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_204(Eurydice_arr_5d *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)5U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_203(Eurydice_arr_5a *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)30U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_202(Eurydice_arr_47 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)11U;
  वापस lit;
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.zero_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल अंतरभूत Eurydice_arr_a3 libcrux_ml_dsa_polynomial_zero_ff_37(व्योम)
{
  Eurydice_arr_a3 lit;
  Eurydice_arr_4d repeat_expression[32U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    repeat_expression[i] = libcrux_ml_dsa_simd_portable_zero_65();
  }
  स_नकल(lit.तथ्य, repeat_expression, (माप_प्रकार)32U * माप (Eurydice_arr_4d));
  वापस lit;
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.from_i32_array_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_polynomial_from_i32_array_ff_37(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_a3 *परिणाम
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_from_coefficient_array_65(Eurydice_slice_subslice_shared_47(array,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT,
            .end = (i0 + (माप_प्रकार)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT
          }
        )),
      &परिणाम->तथ्य[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.use_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_arithmetic_use_hint_37(
  int32_t gamma2,
  Eurydice_dst_ref_shared_20 hint,
  Eurydice_dst_ref_mut_44 re_vector
)
{
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < re_vector.meta; i0++)
  {
    माप_प्रकार i1 = i0;
    Eurydice_arr_a3 tmp = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_to_slice_shared_af(&hint.ptr[i1]),
      &tmp);
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
    {
      माप_प्रकार j = i;
      libcrux_ml_dsa_simd_portable_use_hint_65(gamma2, &re_vector.ptr[i1].तथ्य[j], &tmp.तथ्य[j]);
    }
    re_vector.ptr[i1] = tmp;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt_multiply_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(Eurydice_arr_a3 *lhs, स्थिर Eurydice_arr_a3 *rhs)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_montgomery_multiply_65(&lhs->तथ्य[i0], &rhs->तथ्य[i0]);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_polynomial_add_ff_37(Eurydice_arr_a3 *self, स्थिर Eurydice_arr_a3 *rhs)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_add_65(&self->तथ्य[i0], &rhs->तथ्य[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.arithmetic.shift_left_then_reduce
with const generics
- SHIFT_BY= 13
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_simd_portable_arithmetic_shift_बायाँ_then_reduce_84(Eurydice_arr_4d *simd_unit)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    simd_unit->तथ्य[i0] = (int32_t)((uint32_t)simd_unit->तथ्य[i0] << (uint32_t)13);
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
अटल अंतरभूत व्योम
libcrux_ml_dsa_simd_portable_shift_बायाँ_then_reduce_65_84(Eurydice_arr_4d *simd_unit)
{
  libcrux_ml_dsa_simd_portable_arithmetic_shift_बायाँ_then_reduce_84(simd_unit);
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.shift_left_then_reduce
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- SHIFT_BY= 13
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_arithmetic_shift_बायाँ_then_reduce_68(Eurydice_arr_a3 *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_shift_बायाँ_then_reduce_65_84(&re->तथ्य[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम libcrux_ml_dsa_ntt_ntt_37(Eurydice_arr_a3 *re)
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_polynomial_subtract_ff_37(Eurydice_arr_a3 *self, स्थिर Eurydice_arr_a3 *rhs)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_subtract_65(&self->तथ्य[i0], &rhs->तथ्य[i0]);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(Eurydice_arr_a3 *self)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_barrett_reduce_simd_unit_65(&self->तथ्य[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.invert_ntt_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(Eurydice_arr_a3 *re)
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_matrix_compute_w_approx_37(
  माप_प्रकार rows_in_a,
  माप_प्रकार columns_in_a,
  Eurydice_dst_ref_shared_44 matrix,
  Eurydice_dst_ref_shared_44 signer_response,
  स्थिर Eurydice_arr_a3 *verifier_challenge_as_ntt,
  Eurydice_dst_ref_mut_44 t1
)
{
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < rows_in_a; i0++)
  {
    माप_प्रकार i1 = i0;
    Eurydice_arr_a3 inner_परिणाम = libcrux_ml_dsa_polynomial_zero_ff_37();
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < columns_in_a; i++)
    {
      माप_प्रकार j = i;
      Eurydice_arr_a3 product = matrix.ptr[i1 * columns_in_a + j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&product, &signer_response.ptr[j]);
      libcrux_ml_dsa_polynomial_add_ff_37(&inner_परिणाम, &product);
    }
    libcrux_ml_dsa_arithmetic_shift_बायाँ_then_reduce_68(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&t1.ptr[i1], verifier_challenge_as_ntt);
    libcrux_ml_dsa_polynomial_subtract_ff_37(&inner_परिणाम, &t1.ptr[i1]);
    t1.ptr[i1] = inner_परिणाम;
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&t1.ptr[i1]);
  }
}

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_VerificationError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_41_s
{
  core_परिणाम_परिणाम_57_tags tag;
  libcrux_ml_dsa_types_VerificationError f0;
}
core_परिणाम_परिणाम_41;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_gamma1_deserialize_37(
  माप_प्रकार gamma1_exponent,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_a3 *परिणाम
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (gamma1_exponent + (माप_प्रकार)1U),
            .end = (i0 + (माप_प्रकार)1U) * (gamma1_exponent + (माप_प्रकार)1U)
          }
        )),
      &परिणाम->तथ्य[i0],
      gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signature.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_encoding_signature_deserialize_37(
  माप_प्रकार columns_in_a,
  माप_प्रकार rows_in_a,
  माप_प्रकार commitment_hash_आकार,
  माप_प्रकार gamma1_exponent,
  माप_प्रकार gamma1_ring_element_आकार,
  माप_प्रकार max_ones_in_hint,
  माप_प्रकार signature_आकार,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_mut_borrow_slice_u8 out_commitment_hash,
  Eurydice_dst_ref_mut_44 out_signer_response,
  Eurydice_dst_ref_mut_20 out_hint
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(serialized,
      commitment_hash_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 commitment_hash = uu____0.fst;
  Eurydice_borrow_slice_u8 rest_of_serialized = uu____0.snd;
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(out_commitment_hash,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = commitment_hash_आकार })),
    commitment_hash,
    uint8_t);
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(rest_of_serialized,
      gamma1_ring_element_आकार * columns_in_a,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 signer_response_serialized = uu____1.fst;
  Eurydice_borrow_slice_u8 hint_serialized = uu____1.snd;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < columns_in_a; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
      Eurydice_slice_subslice_shared_c8(signer_response_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * gamma1_ring_element_आकार,
            .end = (i0 + (माप_प्रकार)1U) * gamma1_ring_element_आकार
          }
        )),
      &out_signer_response.ptr[i0]);
  }
  माप_प्रकार previous_true_hints_seen = (माप_प्रकार)0U;
  bool malformed_hint = false;
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < rows_in_a; i0++)
  {
    माप_प्रकार i1 = i0;
    माप_प्रकार current_true_hints_seen = (माप_प्रकार)(uint32_t)hint_serialized.ptr[max_ones_in_hint + i1];
    अगर (current_true_hints_seen < previous_true_hints_seen)
    {
      malformed_hint = true;
      अवरोध;
    }
    अगर (current_true_hints_seen > max_ones_in_hint)
    {
      malformed_hint = true;
      अवरोध;
    }
    क्रम (माप_प्रकार i = previous_true_hints_seen; i < current_true_hints_seen; i++)
    {
      माप_प्रकार j = i;
      अगर (j > previous_true_hints_seen)
      {
        अगर (hint_serialized.ptr[j] <= hint_serialized.ptr[j - (माप_प्रकार)1U])
        {
          malformed_hint = true;
          अवरोध;
        }
      }
      libcrux_ml_dsa_encoding_signature_set_hint(out_hint,
        i1,
        (माप_प्रकार)(uint32_t)hint_serialized.ptr[j]);
    }
    अगर (malformed_hint)
    {
      अवरोध;
    }
    previous_true_hints_seen = current_true_hints_seen;
  }
  क्रम (माप_प्रकार i = previous_true_hints_seen; i < max_ones_in_hint; i++)
  {
    माप_प्रकार j = i;
    अगर (hint_serialized.ptr[j] != 0U)
    {
      malformed_hint = true;
      अवरोध;
    }
  }
  core_परिणाम_परिणाम_41 uu____2;
  अगर (malformed_hint)
  {
    uu____2 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_41){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_MalformedHintError
        }
      );
  }
  अन्यथा
  {
    uu____2 = (KRML_CLITERAL(core_परिणाम_परिणाम_41){ .tag = core_परिणाम_Ok });
  }
  वापस uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_encoding_t1_deserialize_37(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_a3 *परिणाम
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_t1_deserialize_65(Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_WINDOW,
            .end = (i0 + (माप_प्रकार)1U) * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_WINDOW
          }
        )),
      &परिणाम->तथ्य[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_verification_कुंजी_deserialize_37(
  माप_प्रकार rows_in_a,
  माप_प्रकार verification_कुंजी_आकार,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_dst_ref_mut_44 t1
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < rows_in_a; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_encoding_t1_deserialize_37(Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1_S_आकार,
            .end = (i0 + (माप_प्रकार)1U) * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1_S_आकार
          }
        )),
      &t1.ptr[i0]);
  }
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44Signature, libcrux_ml_dsa_types_SigningError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_48_s
{
  core_परिणाम_परिणाम_57_tags tag;
  जोड़ {
    Eurydice_arr_85 case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_परिणाम_परिणाम_48;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $4size_t
*/
प्रकार काष्ठा Eurydice_arr_9d_s { Eurydice_arr_a3 तथ्य[4U]; } Eurydice_arr_9d;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_9d

*/
प्रकार काष्ठा core_option_Option_d9_s
{
  core_option_Option_45_tags tag;
  Eurydice_arr_9d f0;
}
core_option_Option_d9;

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_SigningError

*/
प्रकार काष्ठा core_परिणाम_परिणाम_53_s
{
  core_परिणाम_परिणाम_57_tags tag;
  libcrux_ml_dsa_types_SigningError f0;
}
core_परिणाम_परिणाम_53;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_gamma1_serialize_37(
  स्थिर Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_slice_u8 serialized,
  माप_प्रकार gamma1_exponent
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    स्थिर Eurydice_arr_4d *simd_unit = &re->तथ्य[i0];
    libcrux_ml_dsa_simd_portable_gamma1_serialize_65(simd_unit,
      Eurydice_slice_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (gamma1_exponent + (माप_प्रकार)1U),
            .end = (i0 + (माप_प्रकार)1U) * (gamma1_exponent + (माप_प्रकार)1U)
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_signature_serialize_37(
  Eurydice_borrow_slice_u8 commitment_hash,
  Eurydice_dst_ref_shared_44 signer_response,
  Eurydice_dst_ref_shared_20 hint,
  माप_प्रकार commitment_hash_आकार,
  माप_प्रकार columns_in_a,
  माप_प्रकार rows_in_a,
  माप_प्रकार gamma1_exponent,
  माप_प्रकार gamma1_ring_element_आकार,
  माप_प्रकार max_ones_in_hint,
  Eurydice_mut_borrow_slice_u8 signature
)
{
  माप_प्रकार offset = (माप_प्रकार)0U;
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(signature,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = offset,
          .end = offset + commitment_hash_आकार
        }
      )),
    commitment_hash,
    uint8_t);
  offset += commitment_hash_आकार;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < columns_in_a; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_encoding_gamma1_serialize_37(&signer_response.ptr[i0],
      Eurydice_slice_subslice_mut_c8(signature,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = offset,
            .end = offset + gamma1_ring_element_आकार
          }
        )),
      gamma1_exponent);
    offset += gamma1_ring_element_आकार;
  }
  माप_प्रकार true_hints_seen = (माप_प्रकार)0U;
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < rows_in_a; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)256U; i++)
    {
      माप_प्रकार j = i;
      अगर (hint.ptr[i1].तथ्य[j] == 1)
      {
        signature.ptr[offset + true_hints_seen] = (uint8_t)j;
        true_hints_seen++;
      }
    }
    signature.ptr[offset + max_ones_in_hint + i1] = (uint8_t)true_hints_seen;
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
अटल अंतरभूत Eurydice_arr_6c
libcrux_ml_dsa_polynomial_to_i32_array_ff_37(स्थिर Eurydice_arr_a3 *self)
{
  Eurydice_arr_6c परिणाम = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_to_coefficient_array_65(&self->तथ्य[i0],
      Eurydice_array_to_subslice_mut_44(&परिणाम,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT,
            .end = (i0 + (माप_प्रकार)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_IN_SIMD_UNIT
          }
        )));
  }
  वापस परिणाम;
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.make_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE माप_प्रकार
libcrux_ml_dsa_arithmetic_make_hint_37(
  Eurydice_dst_ref_shared_44 निचला,
  Eurydice_dst_ref_shared_44 ऊपरी,
  int32_t gamma2,
  Eurydice_dst_ref_mut_20 hint
)
{
  माप_प्रकार true_hints = (माप_प्रकार)0U;
  Eurydice_arr_a3 hint_simd = libcrux_ml_dsa_polynomial_zero_ff_37();
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < निचला.meta; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
    {
      माप_प्रकार j = i;
      माप_प्रकार
      one_hints_गिनती =
        libcrux_ml_dsa_simd_portable_compute_hint_65(&निचला.ptr[i1].तथ्य[j],
          &ऊपरी.ptr[i1].तथ्य[j],
          gamma2,
          &hint_simd.तथ्य[j]);
      true_hints += one_hints_गिनती;
    }
    Eurydice_arr_6c uu____0 = libcrux_ml_dsa_polynomial_to_i32_array_ff_37(&hint_simd);
    hint.ptr[i1] = uu____0;
  }
  वापस true_hints;
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
अटल KRML_MUSTINLINE bool
libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(
  स्थिर Eurydice_arr_a3 *self,
  int32_t bound
)
{
  bool परिणाम = false;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    bool
    coeff_exceeds = libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(&self->तथ्य[i0], bound);
    bool uu____0;
    अगर (परिणाम)
    {
      uu____0 = true;
    }
    अन्यथा
    {
      uu____0 = coeff_exceeds;
    }
    परिणाम = uu____0;
  }
  वापस परिणाम;
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
अटल KRML_MUSTINLINE bool
libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(
  Eurydice_dst_ref_shared_44 vector,
  int32_t bound
)
{
  bool परिणाम = false;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < vector.meta; i++)
  {
    माप_प्रकार i0 = i;
    bool uu____0;
    अगर (परिणाम)
    {
      uu____0 = true;
    }
    अन्यथा
    {
      uu____0 = libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(&vector.ptr[i0], bound);
    }
    परिणाम = uu____0;
  }
  वापस परिणाम;
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.subtract_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_matrix_subtract_vectors_37(
  माप_प्रकार dimension,
  Eurydice_dst_ref_mut_44 lhs,
  Eurydice_dst_ref_shared_44 rhs
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < dimension; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_polynomial_subtract_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.add_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_matrix_add_vectors_37(
  माप_प्रकार dimension,
  Eurydice_dst_ref_mut_44 lhs,
  Eurydice_dst_ref_shared_44 rhs
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < dimension; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_polynomial_add_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.vector_times_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_matrix_vector_times_ring_element_37(
  Eurydice_dst_ref_mut_44 vector,
  स्थिर Eurydice_arr_a3 *ring_element
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < vector.meta; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&vector.ptr[i0], ring_element);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&vector.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_commitment_serialize_37(
  स्थिर Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  माप_प्रकार output_bytes_per_simd_unit = serialized.meta / ((माप_प्रकार)8U * (माप_प्रकार)4U);
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    स्थिर Eurydice_arr_4d *simd_unit = &re->तथ्य[i0];
    libcrux_ml_dsa_simd_portable_commitment_serialize_65(simd_unit,
      Eurydice_slice_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * output_bytes_per_simd_unit,
            .end = (i0 + (माप_प्रकार)1U) * output_bytes_per_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_commitment_serialize_vector_37(
  माप_प्रकार ring_element_आकार,
  Eurydice_dst_ref_shared_44 vector,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  माप_प्रकार offset = (माप_प्रकार)0U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < vector.meta; i++)
  {
    माप_प्रकार _cloop_j = i;
    स्थिर Eurydice_arr_a3 *ring_element = &vector.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_commitment_serialize_37(ring_element,
      Eurydice_slice_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = offset,
            .end = offset + ring_element_आकार
          }
        )));
    offset += ring_element_आकार;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.decompose_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_arithmetic_decompose_vector_37(
  माप_प्रकार dimension,
  int32_t gamma2,
  Eurydice_dst_ref_shared_44 t,
  Eurydice_dst_ref_mut_44 निचला,
  Eurydice_dst_ref_mut_44 ऊपरी
)
{
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < dimension; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
    {
      माप_प्रकार j = i;
      libcrux_ml_dsa_simd_portable_decompose_65(gamma2,
        &t.ptr[i1].तथ्य[j],
        &निचला.ptr[i1].तथ्य[j],
        &ऊपरी.ptr[i1].तथ्य[j]);
    }
  }
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $16size_t
*/
प्रकार काष्ठा Eurydice_arr_2f_s { Eurydice_arr_a3 तथ्य[16U]; } Eurydice_arr_2f;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 16
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_201(स्थिर Eurydice_arr_2f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)16U;
  वापस lit;
}

/**
 Compute InvertNTT(Â ◦ ŷ)
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_matrix_x_mask
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_matrix_compute_matrix_x_mask_37(
  माप_प्रकार rows_in_a,
  माप_प्रकार columns_in_a,
  Eurydice_dst_ref_shared_44 matrix,
  Eurydice_dst_ref_shared_44 mask,
  Eurydice_dst_ref_mut_44 परिणाम
)
{
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < rows_in_a; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < columns_in_a; i++)
    {
      माप_प्रकार j = i;
      Eurydice_arr_a3 product = mask.ptr[j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&product, &matrix.ptr[i1 * columns_in_a + j]);
      libcrux_ml_dsa_polynomial_add_ff_37(&परिणाम.ptr[i1], &product);
    }
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&परिणाम.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&परिणाम.ptr[i1]);
  }
}

/**
A monomorphic instance of core.option.Option
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext

*/
प्रकार काष्ठा core_option_Option_84_s
{
  core_option_Option_45_tags tag;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext f0;
}
core_option_Option_84;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_t0_deserialize_37(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_a3 *परिणाम
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_t0_deserialize_65(Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT,
            .end = (i0 + (माप_प्रकार)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT
          }
        )),
      &परिणाम->तथ्य[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_t0_deserialize_to_vector_then_ntt_37(
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_dst_ref_mut_44 ring_elements
)
{
  क्रम
  (माप_प्रकार
    i = (माप_प्रकार)0U;
    i < serialized.meta / LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0_S_आकार;
    i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0_S_आकार,
            .end = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0_S_आकार +
              LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0_S_आकार
          }
        ));
    libcrux_ml_dsa_encoding_t0_deserialize_37(bytes, &ring_elements.ptr[i0]);
    libcrux_ml_dsa_ntt_ntt_37(&ring_elements.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_error_deserialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_arr_a3 *परिणाम
)
{
  माप_प्रकार chunk_आकार = libcrux_ml_dsa_encoding_error_chunk_आकार(eta);
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_simd_portable_error_deserialize_65(eta,
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * chunk_आकार,
            .end = (i0 + (माप_प्रकार)1U) * chunk_आकार
          }
        )),
      &परिणाम->तथ्य[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(
  libcrux_ml_dsa_constants_Eta eta,
  माप_प्रकार ring_element_आकार,
  Eurydice_borrow_slice_u8 serialized,
  Eurydice_dst_ref_mut_44 ring_elements
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < serialized.meta / ring_element_आकार; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * ring_element_आकार,
            .end = i0 * ring_element_आकार + ring_element_आकार
          }
        ));
    libcrux_ml_dsa_encoding_error_deserialize_37(eta, bytes, &ring_elements.ptr[i0]);
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
अटल अंतरभूत Eurydice_arr_85 libcrux_ml_dsa_types_zero_c5_37(व्योम)
{
  वापस (KRML_CLITERAL(Eurydice_arr_85){ .तथ्य = { 0U } });
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_t0_serialize_37(
  स्थिर Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    स्थिर Eurydice_arr_4d *simd_unit = &re->तथ्य[i0];
    libcrux_ml_dsa_simd_portable_t0_serialize_65(simd_unit,
      Eurydice_slice_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT,
            .end = (i0 + (माप_प्रकार)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_BYTES_PER_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_error_serialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  स्थिर Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  माप_प्रकार output_bytes_per_simd_unit = libcrux_ml_dsa_encoding_error_chunk_आकार(eta);
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    स्थिर Eurydice_arr_4d *simd_unit = &re->तथ्य[i0];
    libcrux_ml_dsa_simd_portable_error_serialize_65(eta,
      simd_unit,
      Eurydice_slice_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * output_bytes_per_simd_unit,
            .end = (i0 + (माप_प्रकार)1U) * output_bytes_per_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_t1_serialize_37(
  स्थिर Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
  {
    माप_प्रकार i0 = i;
    स्थिर Eurydice_arr_4d *simd_unit = &re->तथ्य[i0];
    libcrux_ml_dsa_simd_portable_t1_serialize_65(simd_unit,
      Eurydice_slice_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_BYTES_PER_SIMD_UNIT,
            .end = (i0 + (माप_प्रकार)1U) *
              LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_BYTES_PER_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_verification_कुंजी_generate_serialized_37(
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_shared_44 t1,
  Eurydice_mut_borrow_slice_u8 verification_कुंजी_serialized
)
{
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(verification_कुंजी_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)0U,
          .end = LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार
        }
      )),
    seed,
    uint8_t);
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < t1.meta; i++)
  {
    माप_प्रकार i0 = i;
    स्थिर Eurydice_arr_a3 *ring_element = &t1.ptr[i0];
    माप_प्रकार
    offset =
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार +
        i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1_S_आकार;
    libcrux_ml_dsa_encoding_t1_serialize_37(ring_element,
      Eurydice_slice_subslice_mut_c8(verification_कुंजी_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = offset,
            .end = offset + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T1_S_आकार
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.power2round_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_arithmetic_power2round_vector_37(
  Eurydice_dst_ref_mut_44 t,
  Eurydice_dst_ref_mut_44 t1
)
{
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < t.meta; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)32U; i++)
    {
      माप_प्रकार j = i;
      libcrux_ml_dsa_simd_portable_power2round_65(&t.ptr[i1].तथ्य[j], &t1.ptr[i1].तथ्य[j]);
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
अटल KRML_MUSTINLINE व्योम
libcrux_secrets_mem_requests_ct_declassify_f5(स्थिर Eurydice_arr_9d *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_200(स्थिर Eurydice_arr_8f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)8U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 4
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_slice_shared_20(स्थिर Eurydice_arr_9d *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4U;
  वापस lit;
}

/**
 Compute InvertNTT(Â ◦ ŝ₁) + s₂
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_as1_plus_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_matrix_compute_as1_plus_s2_37(
  माप_प्रकार rows_in_a,
  माप_प्रकार columns_in_a,
  Eurydice_dst_ref_mut_44 a_as_ntt,
  Eurydice_dst_ref_shared_44 s1_ntt,
  Eurydice_dst_ref_shared_44 s1_s2,
  Eurydice_dst_ref_mut_44 परिणाम
)
{
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < rows_in_a; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < columns_in_a; i++)
    {
      माप_प्रकार j = i;
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&a_as_ntt.ptr[i1 * columns_in_a + j],
        &s1_ntt.ptr[j]);
      libcrux_ml_dsa_polynomial_add_ff_37(&परिणाम.ptr[i1], &a_as_ntt.ptr[i1 * columns_in_a + j]);
    }
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < परिणाम.meta; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&परिणाम.ptr[i0]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&परिणाम.ptr[i0]);
    libcrux_ml_dsa_polynomial_add_ff_37(&परिणाम.ptr[i0], &s1_s2.ptr[columns_in_a + i0]);
  }
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
अटल अंतरभूत Eurydice_dst_ref_shared_44
Eurydice_array_to_subslice_shared_25(स्थिर Eurydice_arr_8f *a, core_ops_range_Range_87 r)
{
  वापस
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->तथ्य + r.start, .meta = r.end - r.start }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 4
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_201(Eurydice_arr_9d *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)4U;
  वापस lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 16
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_200(Eurydice_arr_2f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)16U;
  वापस lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_field_modulus
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(
  Eurydice_borrow_slice_u8 randomness,
  माप_प्रकार *sampled_coefficients,
  Eurydice_arr_d0 *out
)
{
  bool done = false;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < randomness.meta / (माप_प्रकार)24U; i++)
  {
    माप_प्रकार _cloop_i = i;
    Eurydice_borrow_slice_u8
    random_bytes =
      Eurydice_slice_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = _cloop_i * (माप_प्रकार)24U,
            .end = _cloop_i * (माप_प्रकार)24U + (माप_प्रकार)24U
          }
        ));
    अगर (!done)
    {
      माप_प्रकार
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_field_modulus_65(random_bytes,
          Eurydice_array_to_subslice_from_mut_11(out, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      अगर (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        done = true;
      }
    }
  }
  वापस done;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
अटल अंतरभूत Eurydice_dst_ref_mut_44 Eurydice_array_to_slice_mut_20(Eurydice_arr_8f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->तथ्य;
  lit.meta = (माप_प्रकार)8U;
  वापस lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_4
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(
  Eurydice_borrow_slice_u8 randomness,
  माप_प्रकार *sampled_coefficients,
  Eurydice_arr_d0 *out
)
{
  bool done = false;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < randomness.meta / (माप_प्रकार)4U; i++)
  {
    माप_प्रकार _cloop_i = i;
    Eurydice_borrow_slice_u8
    random_bytes =
      Eurydice_slice_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = _cloop_i * (माप_प्रकार)4U,
            .end = _cloop_i * (माप_प्रकार)4U + (माप_प्रकार)4U
          }
        ));
    अगर (!done)
    {
      माप_प्रकार
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(random_bytes,
          Eurydice_array_to_subslice_from_mut_11(out, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      अगर (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        done = true;
      }
    }
  }
  वापस done;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(
  Eurydice_borrow_slice_u8 randomness,
  माप_प्रकार *sampled_coefficients,
  Eurydice_arr_d0 *out
)
{
  bool done = false;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < randomness.meta / (माप_प्रकार)4U; i++)
  {
    माप_प्रकार _cloop_i = i;
    Eurydice_borrow_slice_u8
    random_bytes =
      Eurydice_slice_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = _cloop_i * (माप_प्रकार)4U,
            .end = _cloop_i * (माप_प्रकार)4U + (माप_प्रकार)4U
          }
        ));
    अगर (!done)
    {
      माप_प्रकार
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(random_bytes,
          Eurydice_array_to_subslice_from_mut_11(out, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      अगर (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        done = true;
      }
    }
  }
  वापस done;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
अटल KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 randomness,
  माप_प्रकार *sampled,
  Eurydice_arr_d0 *out
)
{
  चयन (eta)
  {
    हाल libcrux_ml_dsa_constants_Eta_Two:
      {
        अवरोध;
      }
    हाल libcrux_ml_dsa_constants_Eta_Four:
      {
        वापस
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(randomness,
            sampled,
            out);
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __खाता__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  वापस
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(randomness,
      sampled,
      out);
}

प्रकार काष्ठा libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_कुंजी_Pair_s
{
  Eurydice_arr_e2 signing_कुंजी;
  Eurydice_arr_43 verification_कुंजी;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_कुंजी_Pair;

प्रकार काष्ठा libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_कुंजी_Pair_s
{
  Eurydice_arr_24 signing_कुंजी;
  Eurydice_arr_29 verification_कुंजी;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_कुंजी_Pair;

प्रकार काष्ठा libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_कुंजी_Pair_s
{
  Eurydice_arr_10 signing_कुंजी;
  Eurydice_arr_02 verification_कुंजी;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_कुंजी_Pair;

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा libcrux_mldsa_core_H_DEFINED
#पूर्ण_अगर /* libcrux_mldsa_core_H */

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


#अगर_अघोषित libcrux_ct_ops_H
#घोषणा libcrux_ct_ops_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


/**
 Return 1 if `value` is not zero and 0 otherwise.
*/
अटल KRML_NOINLINE uint8_t libcrux_ml_kem_constant_time_ops_inz(uint8_t मूल्य)
{
  uint16_t value0 = (uint16_t)(uint32_t)मूल्य;
  uint8_t परिणाम = (uint8_t)((uint32_t)core_अंक_u16_wrapping_add(~value0, 1U) >> 8U & 0xFFFFU);
  वापस (uint32_t)परिणाम & 1U;
}

अटल KRML_NOINLINE uint8_t libcrux_ml_kem_constant_time_ops_is_non_zero(uint8_t मूल्य)
{
  वापस libcrux_ml_kem_constant_time_ops_inz(मूल्य);
}

/**
 Return 1 if the bytes of `lhs` and `rhs` do not exactly
 match and 0 otherwise.
*/
अटल KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_time_ops_compare(
  Eurydice_borrow_slice_u8 lhs,
  Eurydice_borrow_slice_u8 rhs
)
{
  uint8_t r = 0U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < lhs.meta; i++)
  {
    माप_प्रकार i0 = i;
    uint8_t nr = (uint32_t)r | ((uint32_t)lhs.ptr[i0] ^ (uint32_t)rhs.ptr[i0]);
    r = nr;
  }
  वापस libcrux_ml_kem_constant_time_ops_is_non_zero(r);
}

अटल KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_time_ops_compare_ciphertexts_in_constant_time(
  Eurydice_borrow_slice_u8 lhs,
  Eurydice_borrow_slice_u8 rhs
)
{
  वापस libcrux_ml_kem_constant_time_ops_compare(lhs, rhs);
}

/**
 If `selector` is not zero, return the bytes in `rhs`; return the bytes in
 `lhs` otherwise.
*/
अटल KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_time_ops_select_ct(
  Eurydice_borrow_slice_u8 lhs,
  Eurydice_borrow_slice_u8 rhs,
  uint8_t selector
)
{
  uint8_t
  mask = core_अंक_u8_wrapping_sub(libcrux_ml_kem_constant_time_ops_is_non_zero(selector), 1U);
  Eurydice_arr_ec out = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार; i++)
  {
    माप_प्रकार i0 = i;
    uint8_t
    outi =
      ((uint32_t)lhs.ptr[i0] & (uint32_t)mask) | ((uint32_t)rhs.ptr[i0] & (~(uint32_t)mask & 0xFFU));
    out.तथ्य[i0] = outi;
  }
  वापस out;
}

अटल KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_time_ops_select_shared_secret_in_constant_time(
  Eurydice_borrow_slice_u8 lhs,
  Eurydice_borrow_slice_u8 rhs,
  uint8_t selector
)
{
  वापस libcrux_ml_kem_constant_time_ops_select_ct(lhs, rhs, selector);
}

अटल KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_time_ops_compare_ciphertexts_select_shared_secret_in_constant_time(
  Eurydice_borrow_slice_u8 lhs_c,
  Eurydice_borrow_slice_u8 rhs_c,
  Eurydice_borrow_slice_u8 lhs_s,
  Eurydice_borrow_slice_u8 rhs_s
)
{
  uint8_t
  selector = libcrux_ml_kem_constant_time_ops_compare_ciphertexts_in_constant_time(lhs_c, rhs_c);
  वापस
    libcrux_ml_kem_constant_time_ops_select_shared_secret_in_constant_time(lhs_s,
      rhs_s,
      selector);
}

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा libcrux_ct_ops_H_DEFINED
#पूर्ण_अगर /* libcrux_ct_ops_H */

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


#अगर_अघोषित libcrux_mldsa_portable_H
#घोषणा libcrux_mldsa_portable_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


प्रकार काष्ठा libcrux_ml_dsa_hash_functions_portable_Shake128X4_s
{
  Eurydice_arr_7c state0;
  Eurydice_arr_7c state1;
  Eurydice_arr_7c state2;
  Eurydice_arr_7c state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake128X4;

प्रकार libcrux_sha3_portable_KeccakState libcrux_ml_dsa_hash_functions_portable_Shake256;

प्रकार काष्ठा libcrux_ml_dsa_hash_functions_portable_Shake256X4_s
{
  Eurydice_arr_7c state0;
  Eurydice_arr_7c state1;
  Eurydice_arr_7c state2;
  Eurydice_arr_7c state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake256X4;

प्रकार libcrux_sha3_portable_incremental_Shake256Xof
libcrux_ml_dsa_hash_functions_portable_Shake256Xof;

अटल KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3
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
  वापस
    (
      KRML_CLITERAL(libcrux_ml_dsa_hash_functions_portable_Shake128X4){
        .state0 = state0,
        .state1 = state1,
        .state2 = state2,
        .state3 = state3
      }
    );
}

अटल KRML_MUSTINLINE Eurydice_arr_7c
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(
  Eurydice_borrow_slice_u8 निवेश
)
{
  Eurydice_arr_7c state = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state, निवेश);
  वापस state;
}

अटल KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3
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
  वापस
    (
      KRML_CLITERAL(libcrux_ml_dsa_hash_functions_portable_Shake256X4){
        .state0 = state0,
        .state1 = state1,
        .state2 = state2,
        .state3 = state3
      }
    );
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake128(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_portable_shake128(out, निवेश);
}

अटल KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_shake256(Eurydice_arr_7c *state)
{
  Eurydice_arr_ff out = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(state,
    Eurydice_array_to_slice_mut_58(&out));
  वापस out;
}

अटल KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_ff out0 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(&state->state0,
    Eurydice_array_to_slice_mut_58(&out0));
  Eurydice_arr_ff out1 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(&state->state1,
    Eurydice_array_to_slice_mut_58(&out1));
  Eurydice_arr_ff out2 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(&state->state2,
    Eurydice_array_to_slice_mut_58(&out2));
  Eurydice_arr_ff out3 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_first_block(&state->state3,
    Eurydice_array_to_slice_mut_58(&out3));
  वापस
    (KRML_CLITERAL(Eurydice_arr_ff_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_squeeze_first_five_blocks(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state,
  Eurydice_arr_d10 *out0,
  Eurydice_arr_d10 *out1,
  Eurydice_arr_d10 *out2,
  Eurydice_arr_d10 *out3
)
{
  libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(&state->state0,
    Eurydice_array_to_slice_mut_4c(out0));
  libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(&state->state1,
    Eurydice_array_to_slice_mut_4c(out1));
  libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(&state->state2,
    Eurydice_array_to_slice_mut_4c(out2));
  libcrux_sha3_portable_incremental_shake128_squeeze_first_five_blocks(&state->state3,
    Eurydice_array_to_slice_mut_4c(out3));
}

अटल KRML_MUSTINLINE Eurydice_arr_c5_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state
)
{
  Eurydice_arr_c5 out0 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_अग्र_block(&state->state0,
    Eurydice_array_to_slice_mut_2c(&out0));
  Eurydice_arr_c5 out1 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_अग्र_block(&state->state1,
    Eurydice_array_to_slice_mut_2c(&out1));
  Eurydice_arr_c5 out2 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_अग्र_block(&state->state2,
    Eurydice_array_to_slice_mut_2c(&out2));
  Eurydice_arr_c5 out3 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_अग्र_block(&state->state3,
    Eurydice_array_to_slice_mut_2c(&out3));
  वापस
    (KRML_CLITERAL(Eurydice_arr_c5_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

अटल KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_shake256(Eurydice_arr_7c *state)
{
  Eurydice_arr_ff out = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_अग्र_block(state,
    Eurydice_array_to_slice_mut_58(&out));
  वापस out;
}

अटल KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_ff out0 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_अग्र_block(&state->state0,
    Eurydice_array_to_slice_mut_58(&out0));
  Eurydice_arr_ff out1 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_अग्र_block(&state->state1,
    Eurydice_array_to_slice_mut_58(&out1));
  Eurydice_arr_ff out2 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_अग्र_block(&state->state2,
    Eurydice_array_to_slice_mut_58(&out2));
  Eurydice_arr_ff out3 = { .तथ्य = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_अग्र_block(&state->state3,
    Eurydice_array_to_slice_mut_58(&out3));
  वापस
    (KRML_CLITERAL(Eurydice_arr_ff_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::Xof for libcrux_ml_dsa::hash_functions::portable::Shake128}
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake128_7b(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128(निवेश, out);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
अटल KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_11(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3
)
{
  वापस libcrux_ml_dsa_hash_functions_portable_init_absorb(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_squeeze_first_five_blocks_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self,
  Eurydice_arr_d10 *out0,
  Eurydice_arr_d10 *out1,
  Eurydice_arr_d10 *out2,
  Eurydice_arr_d10 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_squeeze_first_five_blocks(self, out0, out1, out2, out3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
अटल KRML_MUSTINLINE Eurydice_arr_c5_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self
)
{
  वापस libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
अटल KRML_MUSTINLINE Eurydice_arr_7c
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(Eurydice_borrow_slice_u8 निवेश)
{
  वापस libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(निवेश);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
अटल KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_61(Eurydice_arr_7c *self)
{
  वापस libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
अटल KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_61(Eurydice_arr_7c *self)
{
  वापस libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_hash_functions_portable_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_slice_u8 निवेश
)
{
  libcrux_sha3_portable_incremental_absorb_42(self, निवेश);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_hash_functions_portable_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_slice_u8 निवेश
)
{
  libcrux_sha3_portable_incremental_absorb_final_42(self, निवेश);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
अटल अंतरभूत libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_ml_dsa_hash_functions_portable_init_26(व्योम)
{
  वापस libcrux_sha3_portable_incremental_new_42();
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_hash_functions_portable_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_sha3_portable_incremental_squeeze_42(self, out);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
अटल KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3
)
{
  वापस libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
अटल KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  वापस libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_x4(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
अटल KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  वापस libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_x4(self);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_four_error_ring_elements
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 seed,
  uint16_t start_सूचकांक,
  Eurydice_dst_ref_mut_44 re
)
{
  Eurydice_arr_91 seed0 = libcrux_ml_dsa_sample_add_error_domain_separator(seed, start_सूचकांक);
  Eurydice_arr_91
  seed1 = libcrux_ml_dsa_sample_add_error_domain_separator(seed, (uint32_t)start_सूचकांक + 1U);
  Eurydice_arr_91
  seed2 = libcrux_ml_dsa_sample_add_error_domain_separator(seed, (uint32_t)start_सूचकांक + 2U);
  Eurydice_arr_91
  seed3 = libcrux_ml_dsa_sample_add_error_domain_separator(seed, (uint32_t)start_सूचकांक + 3U);
  libcrux_ml_dsa_hash_functions_portable_Shake256X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(Eurydice_array_to_slice_shared_f1(&seed0),
      Eurydice_array_to_slice_shared_f1(&seed1),
      Eurydice_array_to_slice_shared_f1(&seed2),
      Eurydice_array_to_slice_shared_f1(&seed3));
  Eurydice_arr_ff_x4
  randomnesses0 = libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_x4_9b(&state);
  Eurydice_arr_930
  out =
    { .तथ्य = { { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } } } };
  माप_प्रकार sampled0 = (माप_प्रकार)0U;
  माप_प्रकार sampled1 = (माप_प्रकार)0U;
  माप_प्रकार sampled2 = (माप_प्रकार)0U;
  माप_प्रकार sampled3 = (माप_प्रकार)0U;
  libcrux_ml_dsa_constants_Eta uu____0 = eta;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____0,
      Eurydice_array_to_slice_shared_58(&randomnesses0.fst),
      &sampled0,
      out.तथ्य);
  libcrux_ml_dsa_constants_Eta uu____1 = eta;
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____1,
      Eurydice_array_to_slice_shared_58(&randomnesses0.snd),
      &sampled1,
      &out.तथ्य[1U]);
  libcrux_ml_dsa_constants_Eta uu____2 = eta;
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____2,
      Eurydice_array_to_slice_shared_58(&randomnesses0.thd),
      &sampled2,
      &out.तथ्य[2U]);
  libcrux_ml_dsa_constants_Eta uu____3 = eta;
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____3,
      Eurydice_array_to_slice_shared_58(&randomnesses0.f3),
      &sampled3,
      &out.तथ्य[3U]);
  जबतक (true)
  {
    अगर (done0)
    {
      अगर (done1)
      {
        अगर (done2)
        {
          अगर (done3)
          {
            अवरोध;
          }
          अन्यथा
          {
            Eurydice_arr_ff_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_x4_9b(&state);
            अगर (!done0)
            {
              libcrux_ml_dsa_constants_Eta uu____4 = eta;
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____4,
                  Eurydice_array_to_slice_shared_58(&randomnesses.fst),
                  &sampled0,
                  out.तथ्य);
            }
            अगर (!done1)
            {
              libcrux_ml_dsa_constants_Eta uu____5 = eta;
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____5,
                  Eurydice_array_to_slice_shared_58(&randomnesses.snd),
                  &sampled1,
                  &out.तथ्य[1U]);
            }
            अगर (!done2)
            {
              libcrux_ml_dsa_constants_Eta uu____6 = eta;
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____6,
                  Eurydice_array_to_slice_shared_58(&randomnesses.thd),
                  &sampled2,
                  &out.तथ्य[2U]);
            }
            अगर (!done3)
            {
              libcrux_ml_dsa_constants_Eta uu____7 = eta;
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____7,
                  Eurydice_array_to_slice_shared_58(&randomnesses.f3),
                  &sampled3,
                  &out.तथ्य[3U]);
            }
          }
        }
        अन्यथा
        {
          Eurydice_arr_ff_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_x4_9b(&state);
          अगर (!done0)
          {
            libcrux_ml_dsa_constants_Eta uu____8 = eta;
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____8,
                Eurydice_array_to_slice_shared_58(&randomnesses.fst),
                &sampled0,
                out.तथ्य);
          }
          अगर (!done1)
          {
            libcrux_ml_dsa_constants_Eta uu____9 = eta;
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____9,
                Eurydice_array_to_slice_shared_58(&randomnesses.snd),
                &sampled1,
                &out.तथ्य[1U]);
          }
          अगर (!done2)
          {
            libcrux_ml_dsa_constants_Eta uu____10 = eta;
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____10,
                Eurydice_array_to_slice_shared_58(&randomnesses.thd),
                &sampled2,
                &out.तथ्य[2U]);
          }
          अगर (!done3)
          {
            libcrux_ml_dsa_constants_Eta uu____11 = eta;
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____11,
                Eurydice_array_to_slice_shared_58(&randomnesses.f3),
                &sampled3,
                &out.तथ्य[3U]);
          }
        }
      }
      अन्यथा
      {
        Eurydice_arr_ff_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_x4_9b(&state);
        अगर (!done0)
        {
          libcrux_ml_dsa_constants_Eta uu____12 = eta;
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____12,
              Eurydice_array_to_slice_shared_58(&randomnesses.fst),
              &sampled0,
              out.तथ्य);
        }
        अगर (!done1)
        {
          libcrux_ml_dsa_constants_Eta uu____13 = eta;
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____13,
              Eurydice_array_to_slice_shared_58(&randomnesses.snd),
              &sampled1,
              &out.तथ्य[1U]);
        }
        अगर (!done2)
        {
          libcrux_ml_dsa_constants_Eta uu____14 = eta;
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____14,
              Eurydice_array_to_slice_shared_58(&randomnesses.thd),
              &sampled2,
              &out.तथ्य[2U]);
        }
        अगर (!done3)
        {
          libcrux_ml_dsa_constants_Eta uu____15 = eta;
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____15,
              Eurydice_array_to_slice_shared_58(&randomnesses.f3),
              &sampled3,
              &out.तथ्य[3U]);
        }
      }
    }
    अन्यथा
    {
      Eurydice_arr_ff_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_x4_9b(&state);
      अगर (!done0)
      {
        libcrux_ml_dsa_constants_Eta uu____16 = eta;
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____16,
            Eurydice_array_to_slice_shared_58(&randomnesses.fst),
            &sampled0,
            out.तथ्य);
      }
      अगर (!done1)
      {
        libcrux_ml_dsa_constants_Eta uu____17 = eta;
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____17,
            Eurydice_array_to_slice_shared_58(&randomnesses.snd),
            &sampled1,
            &out.तथ्य[1U]);
      }
      अगर (!done2)
      {
        libcrux_ml_dsa_constants_Eta uu____18 = eta;
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____18,
            Eurydice_array_to_slice_shared_58(&randomnesses.thd),
            &sampled2,
            &out.तथ्य[2U]);
      }
      अगर (!done3)
      {
        libcrux_ml_dsa_constants_Eta uu____19 = eta;
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____19,
            Eurydice_array_to_slice_shared_58(&randomnesses.f3),
            &sampled3,
            &out.तथ्य[3U]);
      }
    }
  }
  माप_प्रकार max0 = (माप_प्रकार)(uint32_t)start_सूचकांक + (माप_प्रकार)4U;
  माप_प्रकार max;
  अगर (re.meta < max0)
  {
    max = re.meta;
  }
  अन्यथा
  {
    max = max0;
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)(uint32_t)start_सूचकांक; i < max; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_to_slice_shared_2c0(&out.तथ्य[i0
        % (माप_प्रकार)4U]),
      &re.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.sample_s1_and_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_mut_44 s1_s2
)
{
  माप_प्रकार len = s1_s2.meta;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < len / (माप_प्रकार)4U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      seed,
      4U * (uint32_t)(uint16_t)i0,
      s1_s2);
  }
  माप_प्रकार remainder = len % (माप_प्रकार)4U;
  अगर (remainder != (माप_प्रकार)0U)
  {
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      seed,
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_63(
  माप_प्रकार columns,
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_mut_44 matrix,
  Eurydice_arr_d10 *rand_stack0,
  Eurydice_arr_d10 *rand_stack1,
  Eurydice_arr_d10 *rand_stack2,
  Eurydice_arr_d10 *rand_stack3,
  Eurydice_dst_ref_mut_33 tmp_ढेर,
  माप_प्रकार start_सूचकांक,
  माप_प्रकार elements_requested
)
{
  Eurydice_arr_31
  seed0 =
    libcrux_ml_dsa_sample_add_domain_separator(seed,
      libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(start_सूचकांक, columns));
  Eurydice_arr_31
  seed1 =
    libcrux_ml_dsa_sample_add_domain_separator(seed,
      libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(start_सूचकांक + (माप_प्रकार)1U,
        columns));
  Eurydice_arr_31
  seed2 =
    libcrux_ml_dsa_sample_add_domain_separator(seed,
      libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(start_सूचकांक + (माप_प्रकार)2U,
        columns));
  Eurydice_arr_31
  seed3 =
    libcrux_ml_dsa_sample_add_domain_separator(seed,
      libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_xy(start_सूचकांक + (माप_प्रकार)3U,
        columns));
  libcrux_ml_dsa_hash_functions_portable_Shake128X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_11(Eurydice_array_to_slice_shared_e9(&seed0),
      Eurydice_array_to_slice_shared_e9(&seed1),
      Eurydice_array_to_slice_shared_e9(&seed2),
      Eurydice_array_to_slice_shared_e9(&seed3));
  libcrux_ml_dsa_hash_functions_portable_squeeze_first_five_blocks_11(&state,
    rand_stack0,
    rand_stack1,
    rand_stack2,
    rand_stack3);
  माप_प्रकार sampled0 = (माप_प्रकार)0U;
  माप_प्रकार sampled1 = (माप_प्रकार)0U;
  माप_प्रकार sampled2 = (माप_प्रकार)0U;
  माप_प्रकार sampled3 = (माप_प्रकार)0U;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_4c(rand_stack0),
      &sampled0,
      tmp_ढेर.ptr);
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_4c(rand_stack1),
      &sampled1,
      &tmp_ढेर.ptr[1U]);
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_4c(rand_stack2),
      &sampled2,
      &tmp_ढेर.ptr[2U]);
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_4c(rand_stack3),
      &sampled3,
      &tmp_ढेर.ptr[3U]);
  जबतक (true)
  {
    अगर (done0)
    {
      अगर (done1)
      {
        अगर (done2)
        {
          अगर (done3)
          {
            अवरोध;
          }
          अन्यथा
          {
            Eurydice_arr_c5_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_11(&state);
            अगर (!done0)
            {
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.fst),
                  &sampled0,
                  tmp_ढेर.ptr);
            }
            अगर (!done1)
            {
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.snd),
                  &sampled1,
                  &tmp_ढेर.ptr[1U]);
            }
            अगर (!done2)
            {
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.thd),
                  &sampled2,
                  &tmp_ढेर.ptr[2U]);
            }
            अगर (!done3)
            {
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.f3),
                  &sampled3,
                  &tmp_ढेर.ptr[3U]);
            }
          }
        }
        अन्यथा
        {
          Eurydice_arr_c5_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_11(&state);
          अगर (!done0)
          {
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.fst),
                &sampled0,
                tmp_ढेर.ptr);
          }
          अगर (!done1)
          {
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.snd),
                &sampled1,
                &tmp_ढेर.ptr[1U]);
          }
          अगर (!done2)
          {
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.thd),
                &sampled2,
                &tmp_ढेर.ptr[2U]);
          }
          अगर (!done3)
          {
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.f3),
                &sampled3,
                &tmp_ढेर.ptr[3U]);
          }
        }
      }
      अन्यथा
      {
        Eurydice_arr_c5_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_11(&state);
        अगर (!done0)
        {
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.fst),
              &sampled0,
              tmp_ढेर.ptr);
        }
        अगर (!done1)
        {
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.snd),
              &sampled1,
              &tmp_ढेर.ptr[1U]);
        }
        अगर (!done2)
        {
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.thd),
              &sampled2,
              &tmp_ढेर.ptr[2U]);
        }
        अगर (!done3)
        {
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.f3),
              &sampled3,
              &tmp_ढेर.ptr[3U]);
        }
      }
    }
    अन्यथा
    {
      Eurydice_arr_c5_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_11(&state);
      अगर (!done0)
      {
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.fst),
            &sampled0,
            tmp_ढेर.ptr);
      }
      अगर (!done1)
      {
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.snd),
            &sampled1,
            &tmp_ढेर.ptr[1U]);
      }
      अगर (!done2)
      {
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.thd),
            &sampled2,
            &tmp_ढेर.ptr[2U]);
      }
      अगर (!done3)
      {
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_field_modulus_37(Eurydice_array_to_slice_shared_2c(&randomnesses.f3),
            &sampled3,
            &tmp_ढेर.ptr[3U]);
      }
    }
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < elements_requested; i++)
  {
    माप_प्रकार k = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_to_slice_shared_2c0(&tmp_ढेर.ptr[k]),
      &matrix.ptr[start_सूचकांक + k]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.matrix_flat
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake128X4
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_samplex4_matrix_flat_63(
  माप_प्रकार columns,
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_mut_44 matrix
)
{
  Eurydice_arr_d10 rand_stack0 = { .तथ्य = { 0U } };
  Eurydice_arr_d10 rand_stack1 = { .तथ्य = { 0U } };
  Eurydice_arr_d10 rand_stack2 = { .तथ्य = { 0U } };
  Eurydice_arr_d10 rand_stack3 = { .तथ्य = { 0U } };
  Eurydice_arr_930
  tmp_ढेर =
    { .तथ्य = { { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } } } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < matrix.meta / (माप_प्रकार)4U + (माप_प्रकार)1U; i++)
  {
    माप_प्रकार start_सूचकांक = i;
    माप_प्रकार start_index0 = start_सूचकांक * (माप_प्रकार)4U;
    अगर (start_index0 >= matrix.meta)
    {
      अवरोध;
    }
    माप_प्रकार elements_requested;
    अगर (start_index0 + (माप_प्रकार)4U <= matrix.meta)
    {
      elements_requested = (माप_प्रकार)4U;
    }
    अन्यथा
    {
      elements_requested = matrix.meta - start_index0;
    }
    libcrux_ml_dsa_sample_sample_up_to_four_ring_elements_flat_63(columns,
      seed,
      matrix,
      &rand_stack0,
      &rand_stack1,
      &rand_stack2,
      &rand_stack3,
      Eurydice_array_to_slice_mut_7e(&tmp_ढेर),
      start_index0,
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
अटल अंतरभूत व्योम
libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(
  माप_प्रकार columns,
  Eurydice_borrow_slice_u8 seed,
  Eurydice_dst_ref_mut_44 matrix
)
{
  libcrux_ml_dsa_samplex4_matrix_flat_63(columns, seed, matrix);
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 64
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake256_c9(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_arr_c7 *out
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_17(out), निवेश);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 64
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_arr_c7 *out
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_c9(निवेश, out);
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signing_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_encoding_signing_कुंजी_generate_serialized_2e(
  libcrux_ml_dsa_constants_Eta eta,
  माप_प्रकार error_ring_element_आकार,
  Eurydice_borrow_slice_u8 seed_matrix,
  Eurydice_borrow_slice_u8 seed_signing,
  Eurydice_borrow_slice_u8 verification_कुंजी,
  Eurydice_dst_ref_shared_44 s1_2,
  Eurydice_dst_ref_shared_44 t0,
  Eurydice_mut_borrow_slice_u8 signing_कुंजी_serialized
)
{
  माप_प्रकार offset = (माप_प्रकार)0U;
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(signing_कुंजी_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = offset,
          .end = offset + LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार
        }
      )),
    seed_matrix,
    uint8_t);
  offset += LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार;
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(signing_कुंजी_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = offset,
          .end = offset + LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_आकार
        }
      )),
    seed_signing,
    uint8_t);
  offset += LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_आकार;
  Eurydice_arr_c7 verification_कुंजी_hash = { .तथ्य = { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(verification_कुंजी,
    &verification_कुंजी_hash);
  Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(signing_कुंजी_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = offset,
          .end = offset + LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_कुंजी_HASH
        }
      )),
    Eurydice_array_to_slice_shared_17(&verification_कुंजी_hash),
    uint8_t);
  offset += LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_कुंजी_HASH;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < s1_2.meta; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_encoding_error_serialize_37(eta,
      &s1_2.ptr[i0],
      Eurydice_slice_subslice_mut_c8(signing_कुंजी_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = offset,
            .end = offset + error_ring_element_आकार
          }
        )));
    offset += error_ring_element_आकार;
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < t0.meta; i++)
  {
    माप_प्रकार _cloop_j = i;
    स्थिर Eurydice_arr_a3 *ring_element = &t0.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_t0_serialize_37(ring_element,
      Eurydice_slice_subslice_mut_c8(signing_कुंजी_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = offset,
            .end = offset + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0_S_आकार
          }
        )));
    offset += LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_OF_T0_S_आकार;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_generate_कुंजी_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_slice_u8 signing_कुंजी,
  Eurydice_mut_borrow_slice_u8 verification_कुंजी
)
{
  Eurydice_arr_89 seed_expanded0 = { .तथ्य = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_to_slice_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .तथ्य = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_to_slice_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_to_slice_mut_78(&seed_expanded0));
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_78(&seed_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 seed_expanded = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(seed_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_ERROR_VECTORS_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_error_vectors = uu____1.fst;
  Eurydice_borrow_slice_u8 seed_for_signing = uu____1.snd;
  Eurydice_arr_8f s1_s2;
  Eurydice_arr_a3 repeat_expression0[8U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s1_s2.तथ्य, repeat_expression0, (माप_प्रकार)8U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    seed_for_error_vectors,
    Eurydice_array_to_slice_mut_20(&s1_s2));
  Eurydice_arr_9d t0;
  Eurydice_arr_a3 repeat_expression1[4U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t0.तथ्य, repeat_expression1, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
  Eurydice_arr_2f a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[16U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(a_as_ntt.तथ्य, repeat_expression2, (माप_प्रकार)16U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
    seed_for_a,
    Eurydice_array_to_slice_mut_200(&a_as_ntt));
  Eurydice_arr_9d s1_ntt;
  Eurydice_arr_a3 repeat_expression3[4U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s1_ntt.तथ्य, repeat_expression3, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_201(&s1_ntt),
    Eurydice_array_to_subslice_shared_25(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)0U,
          .end = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A
        }
      )),
    Eurydice_arr_a3);
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.तथ्य[i0]);
  }
  libcrux_ml_dsa_matrix_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
    Eurydice_array_to_slice_mut_200(&a_as_ntt),
    Eurydice_array_to_slice_shared_20(&s1_ntt),
    Eurydice_array_to_slice_shared_200(&s1_s2),
    Eurydice_array_to_slice_mut_201(&t0));
  Eurydice_arr_9d t1;
  Eurydice_arr_a3 repeat_expression[4U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
  {
    repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t1.तथ्य, repeat_expression, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_vector_37(Eurydice_array_to_slice_mut_201(&t0),
    Eurydice_array_to_slice_mut_201(&t1));
  libcrux_ml_dsa_encoding_verification_कुंजी_generate_serialized_37(seed_for_a,
    Eurydice_array_to_slice_shared_20(&t1),
    verification_कुंजी);
  libcrux_ml_dsa_encoding_signing_कुंजी_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_आकार,
    seed_for_a,
    seed_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_slice_u8){
        .ptr = verification_कुंजी.ptr,
        .meta = verification_कुंजी.meta
      }
    ),
    Eurydice_array_to_slice_shared_200(&s1_s2),
    Eurydice_array_to_slice_shared_20(&t0),
    signing_कुंजी);
}

/**
 Generate key pair.
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_generate_कुंजी_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_10 *signing_कुंजी,
  Eurydice_arr_02 *verification_कुंजी
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_generate_कुंजी_pair_5a(randomness,
    Eurydice_array_to_slice_mut_34(signing_कुंजी),
    Eurydice_array_to_slice_mut_9f0(verification_कुंजी));
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(
  Eurydice_borrow_slice_u8 verification_कुंजी_hash,
  स्थिर core_option_Option_84 *domain_separation_context,
  Eurydice_borrow_slice_u8 message,
  Eurydice_arr_c7 *message_representative
)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake, verification_कुंजी_hash);
  अगर (domain_separation_context->tag == core_option_Some)
  {
    स्थिर
    libcrux_ml_dsa_pre_hash_DomainSeparationContext
    *domain_separation_context0 = &domain_separation_context->f0;
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *uu____0 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_82
    lvalue0 =
      {
        .तथ्य = {
          (uint8_t)core_option__core__option__Option_T__TraitClause_0___is_some(libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0),
            Eurydice_arr_c9,
            bool)
        }
      };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____0,
      Eurydice_array_to_slice_shared_79(&lvalue0));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *uu____1 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_82
    lvalue =
      { .तथ्य = { (uint8_t)libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0).meta } };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____1,
      Eurydice_array_to_slice_shared_79(&lvalue));
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0));
    स्थिर
    core_option_Option_57
    *uu____2 = libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0);
    अगर (uu____2->tag == core_option_Some)
    {
      स्थिर Eurydice_arr_c9 *pre_hash_oid = &uu____2->f0;
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_to_slice_shared_2f(pre_hash_oid));
    }
  }
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake, message);
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_to_slice_mut_17(message_representative));
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 576
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake256_5a(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_arr_220 *out
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_8a(out), निवेश);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 576
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_5a(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3,
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake256_0e(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_arr_20 *out
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_4f(out), निवेश);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 640
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_0e(
  Eurydice_borrow_slice_u8 input0,
  Eurydice_borrow_slice_u8 input1,
  Eurydice_borrow_slice_u8 input2,
  Eurydice_borrow_slice_u8 input3,
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake256_61_0e(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_arr_20 *out
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(निवेश, out);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 576
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_hash_functions_portable_shake256_61_5a(
  Eurydice_borrow_slice_u8 निवेश,
  Eurydice_arr_220 *out
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(निवेश, out);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_sample_sample_mask_ring_element_2e(
  स्थिर Eurydice_arr_91 *seed,
  Eurydice_arr_a3 *परिणाम,
  माप_प्रकार gamma1_exponent
)
{
  चयन (gamma1_exponent)
  {
    हाल 17U:
      {
        अवरोध;
      }
    हाल 19U:
      {
        Eurydice_arr_20 out = { .तथ्य = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_61_0e(Eurydice_array_to_slice_shared_f1(seed),
          &out);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_4f(&out),
          परिणाम);
        वापस;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  Eurydice_arr_220 out = { .तथ्य = { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_5a(Eurydice_array_to_slice_shared_f1(seed),
    &out);
  libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
    Eurydice_array_to_slice_shared_8a(&out),
    परिणाम);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_sample_sample_mask_vector_67(
  माप_प्रकार dimension,
  माप_प्रकार gamma1_exponent,
  स्थिर Eurydice_arr_c7 *seed,
  uint16_t *domain_separator,
  Eurydice_dst_ref_mut_44 mask
)
{
  Eurydice_arr_91
  seed0 =
    libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_17(seed),
      domain_separator[0U]);
  Eurydice_arr_91
  seed1 =
    libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_17(seed),
      (uint32_t)domain_separator[0U] + 1U);
  Eurydice_arr_91
  seed2 =
    libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_17(seed),
      (uint32_t)domain_separator[0U] + 2U);
  Eurydice_arr_91
  seed3 =
    libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_17(seed),
      (uint32_t)domain_separator[0U] + 3U);
  domain_separator[0U] = (uint32_t)domain_separator[0U] + 4U;
  चयन (gamma1_exponent)
  {
    हाल 17U:
      {
        Eurydice_arr_220 out0 = { .तथ्य = { 0U } };
        Eurydice_arr_220 out1 = { .तथ्य = { 0U } };
        Eurydice_arr_220 out2 = { .तथ्य = { 0U } };
        Eurydice_arr_220 out3 = { .तथ्य = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_5a(Eurydice_array_to_slice_shared_f1(&seed0),
          Eurydice_array_to_slice_shared_f1(&seed1),
          Eurydice_array_to_slice_shared_f1(&seed2),
          Eurydice_array_to_slice_shared_f1(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_8a(&out0),
          mask.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_8a(&out1),
          &mask.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_8a(&out2),
          &mask.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_8a(&out3),
          &mask.ptr[3U]);
        अवरोध;
      }
    हाल 19U:
      {
        Eurydice_arr_20 out0 = { .तथ्य = { 0U } };
        Eurydice_arr_20 out1 = { .तथ्य = { 0U } };
        Eurydice_arr_20 out2 = { .तथ्य = { 0U } };
        Eurydice_arr_20 out3 = { .तथ्य = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_0e(Eurydice_array_to_slice_shared_f1(&seed0),
          Eurydice_array_to_slice_shared_f1(&seed1),
          Eurydice_array_to_slice_shared_f1(&seed2),
          Eurydice_array_to_slice_shared_f1(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_4f(&out0),
          mask.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_4f(&out1),
          &mask.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_4f(&out2),
          &mask.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_to_slice_shared_4f(&out3),
          &mask.ptr[3U]);
        अवरोध;
      }
    शेष:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __खाता__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  क्रम (माप_प्रकार i = (माप_प्रकार)4U; i < dimension; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_91
    seed4 =
      libcrux_ml_dsa_sample_add_error_domain_separator(Eurydice_array_to_slice_shared_17(seed),
        domain_separator[0U]);
    domain_separator[0U] = (uint32_t)domain_separator[0U] + 1U;
    libcrux_ml_dsa_sample_sample_mask_ring_element_2e(&seed4, &mask.ptr[i0], gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_challenge_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(
  Eurydice_borrow_slice_u8 seed,
  माप_प्रकार संख्या_of_ones,
  Eurydice_arr_a3 *re
)
{
  Eurydice_arr_7c state = libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(seed);
  Eurydice_arr_ff
  randomness0 = libcrux_ml_dsa_hash_functions_portable_squeeze_first_block_61(&state);
  Eurydice_array_u8x8 arr;
  स_नकल(arr.तथ्य,
    Eurydice_array_to_subslice_shared_d40(&randomness0,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)8U })).ptr,
    (माप_प्रकार)8U * माप (uint8_t));
  uint64_t
  signs =
    core_अंक_u64_from_le_bytes(core_परिणाम_unwrap_26_e0((
          KRML_CLITERAL(core_परिणाम_परिणाम_8e){ .tag = core_परिणाम_Ok, .val = { .case_Ok = arr } }
        )));
  Eurydice_arr_6c परिणाम = { .तथ्य = { 0U } };
  माप_प्रकार out_सूचकांक = (माप_प्रकार)256U - संख्या_of_ones;
  bool
  done =
    libcrux_ml_dsa_sample_inside_out_shuffle(Eurydice_array_to_subslice_from_shared_5f(&randomness0,
        (माप_प्रकार)8U),
      &out_सूचकांक,
      &signs,
      &परिणाम);
  जबतक (true)
  {
    अगर (done)
    {
      अवरोध;
    }
    अन्यथा
    {
      Eurydice_arr_ff
      randomness = libcrux_ml_dsa_hash_functions_portable_squeeze_अग्र_block_61(&state);
      done =
        libcrux_ml_dsa_sample_inside_out_shuffle(Eurydice_array_to_slice_shared_58(&randomness),
          &out_सूचकांक,
          &signs,
          &परिणाम);
    }
  }
  libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_to_slice_shared_af(&परिणाम), re);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_internal_5a(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(signing_कुंजी,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 remaining_serialized0 = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(remaining_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_signing = uu____1.fst;
  Eurydice_borrow_slice_u8 remaining_serialized1 = uu____1.snd;
  Eurydice_borrow_slice_u8_x2
  uu____2 =
    Eurydice_slice_split_at(remaining_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_कुंजी_HASH,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 verification_कुंजी_hash = uu____2.fst;
  Eurydice_borrow_slice_u8 remaining_serialized2 = uu____2.snd;
  Eurydice_borrow_slice_u8_x2
  uu____3 =
    Eurydice_slice_split_at(remaining_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_आकार *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_slice_u8 remaining_serialized = uu____3.snd;
  Eurydice_borrow_slice_u8_x2
  uu____4 =
    Eurydice_slice_split_at(remaining_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_आकार *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_slice_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_9d s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[4U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s1_as_ntt.तथ्य, repeat_expression0, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
  Eurydice_arr_9d s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[4U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s2_as_ntt.तथ्य, repeat_expression1, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
  Eurydice_arr_9d t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[4U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t0_as_ntt.तथ्य, repeat_expression2, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_आकार,
    s1_serialized,
    Eurydice_array_to_slice_mut_201(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_आकार,
    s2_serialized,
    Eurydice_array_to_slice_mut_201(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_to_vector_then_ntt_37(t0_serialized,
    Eurydice_array_to_slice_mut_201(&t0_as_ntt));
  Eurydice_arr_2f matrix;
  Eurydice_arr_a3 repeat_expression3[16U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(matrix.तथ्य, repeat_expression3, (माप_प्रकार)16U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
    seed_for_a,
    Eurydice_array_to_slice_mut_200(&matrix));
  Eurydice_arr_c7 message_representative = { .तथ्य = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(verification_कुंजी_hash,
    &domain_separation_context,
    message,
    &message_representative);
  Eurydice_arr_c7 mask_seed = { .तथ्य = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, seed_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_to_slice_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_to_slice_shared_17(&message_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_to_slice_mut_17(&mask_seed));
  uint16_t domain_separator_for_mask = 0U;
  माप_प्रकार attempt = (माप_प्रकार)0U;
  core_option_Option_14 commitment_hash0 = { .tag = core_option_None };
  core_option_Option_d9 signer_response0 = { .tag = core_option_None };
  core_option_Option_51 hint0 = { .tag = core_option_None };
  जबतक (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_9d mask;
    Eurydice_arr_a3 repeat_expression4[4U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(mask.तथ्य, repeat_expression4, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
    Eurydice_arr_9d w0;
    Eurydice_arr_a3 repeat_expression5[4U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(w0.तथ्य, repeat_expression5, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
    Eurydice_arr_9d commitment;
    Eurydice_arr_a3 repeat_expression6[4U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(commitment.तथ्य, repeat_expression6, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_mask_vector_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
      &mask_seed,
      &domain_separator_for_mask,
      Eurydice_array_to_slice_mut_201(&mask));
    Eurydice_arr_9d a_x_mask;
    Eurydice_arr_a3 repeat_expression[4U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
    {
      repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(a_x_mask.तथ्य, repeat_expression, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
    Eurydice_arr_9d
    mask_ntt =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)4U,
        &mask,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
    {
      माप_प्रकार i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&mask_ntt.तथ्य[i0]);
    }
    libcrux_ml_dsa_matrix_compute_matrix_x_mask_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
      Eurydice_array_to_slice_shared_201(&matrix),
      Eurydice_array_to_slice_shared_20(&mask_ntt),
      Eurydice_array_to_slice_mut_201(&a_x_mask));
    libcrux_ml_dsa_arithmetic_decompose_vector_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
      Eurydice_array_to_slice_shared_20(&a_x_mask),
      Eurydice_array_to_slice_mut_201(&w0),
      Eurydice_array_to_slice_mut_201(&commitment));
    Eurydice_arr_ec commitment_hash_candidate = { .तथ्य = { 0U } };
    Eurydice_arr_d2 commitment_serialized = { .तथ्य = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_vector_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_आकार,
      Eurydice_array_to_slice_shared_20(&commitment),
      Eurydice_array_to_slice_mut_27(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_to_slice_shared_17(&message_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_to_slice_shared_27(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_to_slice_mut_01(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_to_slice_shared_01(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_IN_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_9d
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)4U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    Eurydice_arr_9d
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)4U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_201(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_201(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_matrix_add_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
      Eurydice_array_to_slice_mut_201(&mask),
      Eurydice_array_to_slice_shared_20(&challenge_times_s1));
    libcrux_ml_dsa_matrix_subtract_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
      Eurydice_array_to_slice_mut_201(&w0),
      Eurydice_array_to_slice_shared_20(&challenge_times_s2));
    अगर
    (
      !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_20(&mask),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
    )
    {
      अगर
      (
        !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_20(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
      )
      {
        Eurydice_arr_9d
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)4U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_9d);
        libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_201(&challenge_times_t0),
          &verifier_challenge);
        अगर
        (
          !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_20(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2)
        )
        {
          libcrux_ml_dsa_matrix_add_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
            Eurydice_array_to_slice_mut_201(&w0),
            Eurydice_array_to_slice_shared_20(&challenge_times_t0));
          Eurydice_arr_b7
          hint_candidate =
            {
              .तथ्य = {
                { .तथ्य = { 0U } },
                { .तथ्य = { 0U } },
                { .तथ्य = { 0U } },
                { .तथ्य = { 0U } }
              }
            };
          माप_प्रकार
          ones_in_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_to_slice_shared_20(&w0),
              Eurydice_array_to_slice_shared_20(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
              Eurydice_array_to_slice_mut_86(&hint_candidate));
          अगर (!(ones_in_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_IN_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_14){
                  .tag = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_d9){ .tag = core_option_Some, .f0 = mask });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_51){
                  .tag = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_परिणाम_परिणाम_53 uu____5;
  अगर (commitment_hash0.tag == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_53){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  अन्यथा
  {
    Eurydice_arr_ec commitment_hash = commitment_hash0.f0;
    Eurydice_arr_ec commitment_hash1 = commitment_hash;
    अगर (signer_response0.tag == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_53){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    अन्यथा
    {
      Eurydice_arr_9d signer_response = signer_response0.f0;
      Eurydice_arr_9d signer_response1 = signer_response;
      अगर (!(hint0.tag == core_option_None))
      {
        Eurydice_arr_b7 hint = hint0.f0;
        Eurydice_arr_b7 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_to_slice_shared_01(&commitment_hash1),
          Eurydice_array_to_slice_shared_20(&signer_response1),
          Eurydice_array_to_slice_shared_86(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_आकार,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_आकार,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_IN_HINT,
          Eurydice_array_to_slice_mut_0d(signature));
        वापस (KRML_CLITERAL(core_परिणाम_परिणाम_53){ .tag = core_परिणाम_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_53){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  वापस uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  core_परिणाम_परिणाम_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .tag = core_option_None }));
  अगर (!(uu____0.tag == core_परिणाम_Ok))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_53){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_internal_5a(signing_कुंजी,
      message,
      (
        KRML_CLITERAL(core_option_Option_84){
          .tag = core_option_Some,
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
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_48
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_5a(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_85 signature = libcrux_ml_dsa_types_zero_c5_37();
  core_परिणाम_परिणाम_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(signing_कुंजी,
      message,
      context,
      randomness,
      &signature);
  core_परिणाम_परिणाम_48 uu____1;
  अगर (uu____0.tag == core_परिणाम_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_48){
          .tag = core_परिणाम_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  अन्यथा
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_परिणाम_परिणाम_48){ .tag = core_परिणाम_Err, .val = { .case_Err = e } });
  }
  वापस uu____1;
}

/**
 Sign.
*/
अटल अंतरभूत core_परिणाम_परिणाम_48
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign(
  स्थिर Eurydice_arr_10 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_5a(Eurydice_array_to_slice_shared_34(signing_कुंजी),
      message,
      context,
      randomness);
}

/**
 Sign.
*/
अटल अंतरभूत core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_mut(
  स्थिर Eurydice_arr_10 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(Eurydice_array_to_slice_shared_34(signing_कुंजी),
      message,
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_pre_hash_hash_30_83(
  Eurydice_borrow_slice_u8 message,
  Eurydice_mut_borrow_slice_u8 output
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128_7b(message, output);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_mut_3f(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  अगर (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(message, pre_hash_बफर);
    core_परिणाम_परिणाम_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .tag = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    अगर (!(uu____0.tag == core_परिणाम_Ok))
    {
      वापस
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_53){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    वापस
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_internal_5a(signing_कुंजी,
        (
          KRML_CLITERAL(Eurydice_borrow_slice_u8){
            .ptr = pre_hash_बफर.ptr,
            .meta = pre_hash_बफर.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .tag = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  वापस
    (
      KRML_CLITERAL(core_परिणाम_परिणाम_53){
        .tag = core_परिणाम_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_48
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_3f(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_85 signature = libcrux_ml_dsa_types_zero_c5_37();
  core_परिणाम_परिणाम_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_mut_3f(signing_कुंजी,
      message,
      context,
      pre_hash_बफर,
      randomness,
      &signature);
  core_परिणाम_परिणाम_48 uu____1;
  अगर (uu____0.tag == core_परिणाम_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_48){
          .tag = core_परिणाम_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  अन्यथा
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_परिणाम_परिणाम_48){ .tag = core_परिणाम_Err, .val = { .case_Err = e } });
  }
  वापस uu____1;
}

/**
 Sign (pre-hashed).
*/
अटल अंतरभूत core_परिणाम_परिणाम_48
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_pre_hashed_shake128(
  स्थिर Eurydice_arr_10 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_3f(Eurydice_array_to_slice_shared_34(signing_कुंजी),
      message,
      context,
      pre_hash_बफर,
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
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_internal_5a(
  स्थिर Eurydice_arr_02 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  core_option_Option_84 domain_separation_context,
  स्थिर Eurydice_arr_85 *signature_serialized
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_9f(verification_कुंजी),
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_9d t1;
  Eurydice_arr_a3 repeat_expression0[4U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t1.तथ्य, repeat_expression0, (माप_प्रकार)4U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_कुंजी_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_VERIFICATION_कुंजी_आकार,
    t1_serialized,
    Eurydice_array_to_slice_mut_201(&t1));
  Eurydice_arr_ec deserialized_commitment_hash = { .तथ्य = { 0U } };
  Eurydice_arr_9d deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[4U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(deserialized_signer_response.तथ्य,
    repeat_expression1,
    (माप_प्रकार)4U * माप (Eurydice_arr_a3));
  Eurydice_arr_b7
  deserialized_hint =
    { .तथ्य = { { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } } } };
  core_परिणाम_परिणाम_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_आकार,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_आकार,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_IN_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNATURE_आकार,
      Eurydice_array_to_slice_shared_0d(signature_serialized),
      Eurydice_array_to_slice_mut_01(&deserialized_commitment_hash),
      Eurydice_array_to_slice_mut_201(&deserialized_signer_response),
      Eurydice_array_to_slice_mut_86(&deserialized_hint));
  core_परिणाम_परिणाम_41 uu____2;
  अगर (uu____1.tag == core_परिणाम_Ok)
  {
    अगर
    (
      libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_20(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_41){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    अन्यथा
    {
      Eurydice_arr_2f matrix;
      Eurydice_arr_a3 repeat_expression[16U];
      क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
      {
        repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      स_नकल(matrix.तथ्य, repeat_expression, (माप_प्रकार)16U * माप (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
        seed_for_a,
        Eurydice_array_to_slice_mut_200(&matrix));
      Eurydice_arr_c7 verification_कुंजी_hash = { .तथ्य = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_to_slice_shared_9f(verification_कुंजी),
        &verification_कुंजी_hash);
      Eurydice_arr_c7 message_representative = { .तथ्य = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(Eurydice_array_to_slice_shared_17(&verification_कुंजी_hash),
        &domain_separation_context,
        message,
        &message_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_to_slice_shared_01(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_IN_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)4U; i++)
      {
        माप_प्रकार i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.तथ्य[i0]);
      }
      libcrux_ml_dsa_matrix_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ROWS_IN_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_IN_A,
        Eurydice_array_to_slice_shared_201(&matrix),
        Eurydice_array_to_slice_shared_20(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_to_slice_mut_201(&t1));
      Eurydice_arr_ec recomputed_commitment_hash = { .तथ्य = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
        Eurydice_array_to_slice_shared_86(&deserialized_hint),
        Eurydice_array_to_slice_mut_201(&t1));
      Eurydice_arr_d2 commitment_serialized = { .तथ्य = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_vector_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_आकार,
        Eurydice_array_to_slice_shared_20(&t1),
        Eurydice_array_to_slice_mut_27(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_to_slice_shared_17(&message_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_to_slice_shared_27(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_to_slice_mut_01(&recomputed_commitment_hash));
      अगर
      (
        Eurydice_array_eq((माप_प्रकार)32U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_परिणाम_परिणाम_41){ .tag = core_परिणाम_Ok });
      }
      अन्यथा
      {
        uu____2 =
          (
            KRML_CLITERAL(core_परिणाम_परिणाम_41){
              .tag = core_परिणाम_Err,
              .f0 = libcrux_ml_dsa_types_VerificationError_CommitmentHashesDontMatchError
            }
          );
      }
    }
  }
  अन्यथा
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_परिणाम_परिणाम_41){ .tag = core_परिणाम_Err, .f0 = e });
  }
  वापस uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_5a(
  स्थिर Eurydice_arr_02 *verification_कुंजी_serialized,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_85 *signature_serialized
)
{
  core_परिणाम_परिणाम_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .tag = core_option_None }));
  अगर (!(uu____0.tag == core_परिणाम_Ok))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_41){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_internal_5a(verification_कुंजी_serialized,
      message,
      (
        KRML_CLITERAL(core_option_Option_84){
          .tag = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify(
  स्थिर Eurydice_arr_02 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_85 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_5a(verification_कुंजी,
      message,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_pre_hashed_3f(
  स्थिर Eurydice_arr_02 *verification_कुंजी_serialized,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  स्थिर Eurydice_arr_85 *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(message, pre_hash_बफर);
  core_परिणाम_परिणाम_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .tag = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  अगर (!(uu____0.tag == core_परिणाम_Ok))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_41){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_internal_5a(verification_कुंजी_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_slice_u8){
          .ptr = pre_hash_बफर.ptr,
          .meta = pre_hash_बफर.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .tag = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify_pre_hashed_shake128(
  स्थिर Eurydice_arr_02 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  स्थिर Eurydice_arr_85 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_pre_hashed_3f(verification_कुंजी,
      message,
      context,
      pre_hash_बफर,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_कुंजी_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_slice_u8 signing_कुंजी,
  Eurydice_mut_borrow_slice_u8 verification_कुंजी
)
{
  Eurydice_arr_89 seed_expanded0 = { .तथ्य = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_to_slice_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .तथ्य = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_to_slice_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_to_slice_mut_78(&seed_expanded0));
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_78(&seed_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 seed_expanded = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(seed_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_ERROR_VECTORS_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_error_vectors = uu____1.fst;
  Eurydice_borrow_slice_u8 seed_for_signing = uu____1.snd;
  Eurydice_arr_47 s1_s2;
  Eurydice_arr_a3 repeat_expression0[11U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)11U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s1_s2.तथ्य, repeat_expression0, (माप_प्रकार)11U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    seed_for_error_vectors,
    Eurydice_array_to_slice_mut_202(&s1_s2));
  Eurydice_arr_dc1 t0;
  Eurydice_arr_a3 repeat_expression1[6U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t0.तथ्य, repeat_expression1, (माप_प्रकार)6U * माप (Eurydice_arr_a3));
  Eurydice_arr_5a a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[30U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)30U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(a_as_ntt.तथ्य, repeat_expression2, (माप_प्रकार)30U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
    seed_for_a,
    Eurydice_array_to_slice_mut_203(&a_as_ntt));
  Eurydice_arr_5d s1_ntt;
  Eurydice_arr_a3 repeat_expression3[5U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)5U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s1_ntt.तथ्य, repeat_expression3, (माप_प्रकार)5U * माप (Eurydice_arr_a3));
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_204(&s1_ntt),
    Eurydice_array_to_subslice_shared_250(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)0U,
          .end = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A
        }
      )),
    Eurydice_arr_a3);
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)5U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.तथ्य[i0]);
  }
  libcrux_ml_dsa_matrix_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
    Eurydice_array_to_slice_mut_203(&a_as_ntt),
    Eurydice_array_to_slice_shared_202(&s1_ntt),
    Eurydice_array_to_slice_shared_203(&s1_s2),
    Eurydice_array_to_slice_mut_205(&t0));
  Eurydice_arr_dc1 t1;
  Eurydice_arr_a3 repeat_expression[6U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)6U; i++)
  {
    repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t1.तथ्य, repeat_expression, (माप_प्रकार)6U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_vector_37(Eurydice_array_to_slice_mut_205(&t0),
    Eurydice_array_to_slice_mut_205(&t1));
  libcrux_ml_dsa_encoding_verification_कुंजी_generate_serialized_37(seed_for_a,
    Eurydice_array_to_slice_shared_204(&t1),
    verification_कुंजी);
  libcrux_ml_dsa_encoding_signing_कुंजी_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_आकार,
    seed_for_a,
    seed_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_slice_u8){
        .ptr = verification_कुंजी.ptr,
        .meta = verification_कुंजी.meta
      }
    ),
    Eurydice_array_to_slice_shared_203(&s1_s2),
    Eurydice_array_to_slice_shared_204(&t0),
    signing_कुंजी);
}

/**
 Generate key pair.
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_कुंजी_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_24 *signing_कुंजी,
  Eurydice_arr_29 *verification_कुंजी
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_कुंजी_pair_5a(randomness,
    Eurydice_array_to_slice_mut_98(signing_कुंजी),
    Eurydice_array_to_slice_mut_37(verification_कुंजी));
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_internal_5a(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(signing_कुंजी,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 remaining_serialized0 = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(remaining_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_signing = uu____1.fst;
  Eurydice_borrow_slice_u8 remaining_serialized1 = uu____1.snd;
  Eurydice_borrow_slice_u8_x2
  uu____2 =
    Eurydice_slice_split_at(remaining_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_कुंजी_HASH,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 verification_कुंजी_hash = uu____2.fst;
  Eurydice_borrow_slice_u8 remaining_serialized2 = uu____2.snd;
  Eurydice_borrow_slice_u8_x2
  uu____3 =
    Eurydice_slice_split_at(remaining_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_आकार *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_slice_u8 remaining_serialized = uu____3.snd;
  Eurydice_borrow_slice_u8_x2
  uu____4 =
    Eurydice_slice_split_at(remaining_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_आकार *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_slice_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_5d s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[5U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)5U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s1_as_ntt.तथ्य, repeat_expression0, (माप_प्रकार)5U * माप (Eurydice_arr_a3));
  Eurydice_arr_dc1 s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[6U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s2_as_ntt.तथ्य, repeat_expression1, (माप_प्रकार)6U * माप (Eurydice_arr_a3));
  Eurydice_arr_dc1 t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[6U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)6U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t0_as_ntt.तथ्य, repeat_expression2, (माप_प्रकार)6U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_आकार,
    s1_serialized,
    Eurydice_array_to_slice_mut_204(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_आकार,
    s2_serialized,
    Eurydice_array_to_slice_mut_205(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_to_vector_then_ntt_37(t0_serialized,
    Eurydice_array_to_slice_mut_205(&t0_as_ntt));
  Eurydice_arr_5a matrix;
  Eurydice_arr_a3 repeat_expression3[30U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)30U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(matrix.तथ्य, repeat_expression3, (माप_प्रकार)30U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
    seed_for_a,
    Eurydice_array_to_slice_mut_203(&matrix));
  Eurydice_arr_c7 message_representative = { .तथ्य = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(verification_कुंजी_hash,
    &domain_separation_context,
    message,
    &message_representative);
  Eurydice_arr_c7 mask_seed = { .तथ्य = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, seed_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_to_slice_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_to_slice_shared_17(&message_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_to_slice_mut_17(&mask_seed));
  uint16_t domain_separator_for_mask = 0U;
  माप_प्रकार attempt = (माप_प्रकार)0U;
  core_option_Option_81 commitment_hash0 = { .tag = core_option_None };
  core_option_Option_1e signer_response0 = { .tag = core_option_None };
  core_option_Option_05 hint0 = { .tag = core_option_None };
  जबतक (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_5d mask;
    Eurydice_arr_a3 repeat_expression4[5U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)5U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(mask.तथ्य, repeat_expression4, (माप_प्रकार)5U * माप (Eurydice_arr_a3));
    Eurydice_arr_dc1 w0;
    Eurydice_arr_a3 repeat_expression5[6U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)6U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(w0.तथ्य, repeat_expression5, (माप_प्रकार)6U * माप (Eurydice_arr_a3));
    Eurydice_arr_dc1 commitment;
    Eurydice_arr_a3 repeat_expression6[6U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)6U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(commitment.तथ्य, repeat_expression6, (माप_प्रकार)6U * माप (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_mask_vector_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      &mask_seed,
      &domain_separator_for_mask,
      Eurydice_array_to_slice_mut_204(&mask));
    Eurydice_arr_dc1 a_x_mask;
    Eurydice_arr_a3 repeat_expression[6U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)6U; i++)
    {
      repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(a_x_mask.तथ्य, repeat_expression, (माप_प्रकार)6U * माप (Eurydice_arr_a3));
    Eurydice_arr_5d
    mask_ntt =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)5U,
        &mask,
        Eurydice_arr_a3,
        Eurydice_arr_5d);
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)5U; i++)
    {
      माप_प्रकार i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&mask_ntt.तथ्य[i0]);
    }
    libcrux_ml_dsa_matrix_compute_matrix_x_mask_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      Eurydice_array_to_slice_shared_205(&matrix),
      Eurydice_array_to_slice_shared_202(&mask_ntt),
      Eurydice_array_to_slice_mut_205(&a_x_mask));
    libcrux_ml_dsa_arithmetic_decompose_vector_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
      Eurydice_array_to_slice_shared_204(&a_x_mask),
      Eurydice_array_to_slice_mut_205(&w0),
      Eurydice_array_to_slice_mut_205(&commitment));
    Eurydice_arr_65 commitment_hash_candidate = { .तथ्य = { 0U } };
    Eurydice_arr_d2 commitment_serialized = { .तथ्य = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_vector_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_आकार,
      Eurydice_array_to_slice_shared_204(&commitment),
      Eurydice_array_to_slice_mut_27(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_to_slice_shared_17(&message_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_to_slice_shared_27(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_to_slice_mut_9f(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_to_slice_shared_9f0(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_IN_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_5d
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)5U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_5d);
    Eurydice_arr_dc1
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)6U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_dc1);
    libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_204(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_205(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_matrix_add_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      Eurydice_array_to_slice_mut_204(&mask),
      Eurydice_array_to_slice_shared_202(&challenge_times_s1));
    libcrux_ml_dsa_matrix_subtract_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      Eurydice_array_to_slice_mut_205(&w0),
      Eurydice_array_to_slice_shared_204(&challenge_times_s2));
    अगर
    (
      !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_202(&mask),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      अगर
      (
        !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_204(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
      )
      {
        Eurydice_arr_dc1
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)6U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_dc1);
        libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_205(&challenge_times_t0),
          &verifier_challenge);
        अगर
        (
          !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_204(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2)
        )
        {
          libcrux_ml_dsa_matrix_add_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
            Eurydice_array_to_slice_mut_205(&w0),
            Eurydice_array_to_slice_shared_204(&challenge_times_t0));
          Eurydice_arr_5d0
          hint_candidate =
            {
              .तथ्य = {
                { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } },
                { .तथ्य = { 0U } }, { .तथ्य = { 0U } }
              }
            };
          माप_प्रकार
          ones_in_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_to_slice_shared_204(&w0),
              Eurydice_array_to_slice_shared_204(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
              Eurydice_array_to_slice_mut_860(&hint_candidate));
          अगर (!(ones_in_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_81){
                  .tag = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_1e){ .tag = core_option_Some, .f0 = mask });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_05){
                  .tag = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_परिणाम_परिणाम_53 uu____5;
  अगर (commitment_hash0.tag == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_53){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  अन्यथा
  {
    Eurydice_arr_65 commitment_hash = commitment_hash0.f0;
    Eurydice_arr_65 commitment_hash1 = commitment_hash;
    अगर (signer_response0.tag == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_53){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    अन्यथा
    {
      Eurydice_arr_5d signer_response = signer_response0.f0;
      Eurydice_arr_5d signer_response1 = signer_response;
      अगर (!(hint0.tag == core_option_None))
      {
        Eurydice_arr_5d0 hint = hint0.f0;
        Eurydice_arr_5d0 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_to_slice_shared_9f0(&commitment_hash1),
          Eurydice_array_to_slice_shared_202(&signer_response1),
          Eurydice_array_to_slice_shared_860(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_आकार,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_आकार,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT,
          Eurydice_array_to_slice_mut_6b(signature));
        वापस (KRML_CLITERAL(core_परिणाम_परिणाम_53){ .tag = core_परिणाम_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_53){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  वापस uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  core_परिणाम_परिणाम_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .tag = core_option_None }));
  अगर (!(uu____0.tag == core_परिणाम_Ok))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_53){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_internal_5a(signing_कुंजी,
      message,
      (
        KRML_CLITERAL(core_option_Option_84){
          .tag = core_option_Some,
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
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_8c
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_0c signature = libcrux_ml_dsa_types_zero_c5_5c();
  core_परिणाम_परिणाम_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(signing_कुंजी,
      message,
      context,
      randomness,
      &signature);
  core_परिणाम_परिणाम_8c uu____1;
  अगर (uu____0.tag == core_परिणाम_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_8c){
          .tag = core_परिणाम_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  अन्यथा
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_परिणाम_परिणाम_8c){ .tag = core_परिणाम_Err, .val = { .case_Err = e } });
  }
  वापस uu____1;
}

/**
 Sign.
*/
अटल अंतरभूत core_परिणाम_परिणाम_8c
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(
  स्थिर Eurydice_arr_24 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(Eurydice_array_to_slice_shared_98(signing_कुंजी),
      message,
      context,
      randomness);
}

/**
 Sign.
*/
अटल अंतरभूत core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(
  स्थिर Eurydice_arr_24 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(Eurydice_array_to_slice_shared_98(signing_कुंजी),
      message,
      context,
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  अगर (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(message, pre_hash_बफर);
    core_परिणाम_परिणाम_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .tag = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    अगर (!(uu____0.tag == core_परिणाम_Ok))
    {
      वापस
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_53){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    वापस
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_internal_5a(signing_कुंजी,
        (
          KRML_CLITERAL(Eurydice_borrow_slice_u8){
            .ptr = pre_hash_बफर.ptr,
            .meta = pre_hash_बफर.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .tag = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  वापस
    (
      KRML_CLITERAL(core_परिणाम_परिणाम_53){
        .tag = core_परिणाम_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_8c
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_0c signature = libcrux_ml_dsa_types_zero_c5_5c();
  core_परिणाम_परिणाम_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(signing_कुंजी,
      message,
      context,
      pre_hash_बफर,
      randomness,
      &signature);
  core_परिणाम_परिणाम_8c uu____1;
  अगर (uu____0.tag == core_परिणाम_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_8c){
          .tag = core_परिणाम_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  अन्यथा
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_परिणाम_परिणाम_8c){ .tag = core_परिणाम_Err, .val = { .case_Err = e } });
  }
  वापस uu____1;
}

/**
 Sign (pre-hashed).
*/
अटल अंतरभूत core_परिणाम_परिणाम_8c
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(
  स्थिर Eurydice_arr_24 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(Eurydice_array_to_slice_shared_98(signing_कुंजी),
      message,
      context,
      pre_hash_बफर,
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
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_internal_5a(
  स्थिर Eurydice_arr_29 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  core_option_Option_84 domain_separation_context,
  स्थिर Eurydice_arr_0c *signature_serialized
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_37(verification_कुंजी),
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_dc1 t1;
  Eurydice_arr_a3 repeat_expression0[6U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)6U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t1.तथ्य, repeat_expression0, (माप_प्रकार)6U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_कुंजी_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_कुंजी_आकार,
    t1_serialized,
    Eurydice_array_to_slice_mut_205(&t1));
  Eurydice_arr_65 deserialized_commitment_hash = { .तथ्य = { 0U } };
  Eurydice_arr_5d deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[5U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)5U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(deserialized_signer_response.तथ्य,
    repeat_expression1,
    (माप_प्रकार)5U * माप (Eurydice_arr_a3));
  Eurydice_arr_5d0
  deserialized_hint =
    {
      .तथ्य = {
        { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } },
        { .तथ्य = { 0U } }, { .तथ्य = { 0U } }
      }
    };
  core_परिणाम_परिणाम_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_आकार,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_आकार,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_IN_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_आकार,
      Eurydice_array_to_slice_shared_6b(signature_serialized),
      Eurydice_array_to_slice_mut_9f(&deserialized_commitment_hash),
      Eurydice_array_to_slice_mut_204(&deserialized_signer_response),
      Eurydice_array_to_slice_mut_860(&deserialized_hint));
  core_परिणाम_परिणाम_41 uu____2;
  अगर (uu____1.tag == core_परिणाम_Ok)
  {
    अगर
    (
      libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_202(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_41){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    अन्यथा
    {
      Eurydice_arr_5a matrix;
      Eurydice_arr_a3 repeat_expression[30U];
      क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)30U; i++)
      {
        repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      स_नकल(matrix.तथ्य, repeat_expression, (माप_प्रकार)30U * माप (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
        seed_for_a,
        Eurydice_array_to_slice_mut_203(&matrix));
      Eurydice_arr_c7 verification_कुंजी_hash = { .तथ्य = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_to_slice_shared_37(verification_कुंजी),
        &verification_कुंजी_hash);
      Eurydice_arr_c7 message_representative = { .तथ्य = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(Eurydice_array_to_slice_shared_17(&verification_कुंजी_hash),
        &domain_separation_context,
        message,
        &message_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_to_slice_shared_9f0(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_IN_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)5U; i++)
      {
        माप_प्रकार i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.तथ्य[i0]);
      }
      libcrux_ml_dsa_matrix_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ROWS_IN_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_IN_A,
        Eurydice_array_to_slice_shared_205(&matrix),
        Eurydice_array_to_slice_shared_202(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_to_slice_mut_205(&t1));
      Eurydice_arr_65 recomputed_commitment_hash = { .तथ्य = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
        Eurydice_array_to_slice_shared_860(&deserialized_hint),
        Eurydice_array_to_slice_mut_205(&t1));
      Eurydice_arr_d2 commitment_serialized = { .तथ्य = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_vector_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_आकार,
        Eurydice_array_to_slice_shared_204(&t1),
        Eurydice_array_to_slice_mut_27(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_to_slice_shared_17(&message_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_to_slice_shared_27(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_to_slice_mut_9f(&recomputed_commitment_hash));
      अगर
      (
        Eurydice_array_eq((माप_प्रकार)48U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_परिणाम_परिणाम_41){ .tag = core_परिणाम_Ok });
      }
      अन्यथा
      {
        uu____2 =
          (
            KRML_CLITERAL(core_परिणाम_परिणाम_41){
              .tag = core_परिणाम_Err,
              .f0 = libcrux_ml_dsa_types_VerificationError_CommitmentHashesDontMatchError
            }
          );
      }
    }
  }
  अन्यथा
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_परिणाम_परिणाम_41){ .tag = core_परिणाम_Err, .f0 = e });
  }
  वापस uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(
  स्थिर Eurydice_arr_29 *verification_कुंजी_serialized,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_0c *signature_serialized
)
{
  core_परिणाम_परिणाम_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .tag = core_option_None }));
  अगर (!(uu____0.tag == core_परिणाम_Ok))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_41){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_internal_5a(verification_कुंजी_serialized,
      message,
      (
        KRML_CLITERAL(core_option_Option_84){
          .tag = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(
  स्थिर Eurydice_arr_29 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_0c *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(verification_कुंजी,
      message,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(
  स्थिर Eurydice_arr_29 *verification_कुंजी_serialized,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  स्थिर Eurydice_arr_0c *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(message, pre_hash_बफर);
  core_परिणाम_परिणाम_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .tag = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  अगर (!(uu____0.tag == core_परिणाम_Ok))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_41){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_internal_5a(verification_कुंजी_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_slice_u8){
          .ptr = pre_hash_बफर.ptr,
          .meta = pre_hash_बफर.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .tag = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(
  स्थिर Eurydice_arr_29 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  स्थिर Eurydice_arr_0c *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(verification_कुंजी,
      message,
      context,
      pre_hash_बफर,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_generate_कुंजी_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_slice_u8 signing_कुंजी,
  Eurydice_mut_borrow_slice_u8 verification_कुंजी
)
{
  Eurydice_arr_89 seed_expanded0 = { .तथ्य = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_to_slice_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .तथ्य = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_to_slice_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_to_slice_mut_78(&seed_expanded0));
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_78(&seed_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 seed_expanded = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(seed_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_ERROR_VECTORS_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_error_vectors = uu____1.fst;
  Eurydice_borrow_slice_u8 seed_for_signing = uu____1.snd;
  Eurydice_arr_92 s1_s2;
  Eurydice_arr_a3 repeat_expression0[15U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)15U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s1_s2.तथ्य, repeat_expression0, (माप_प्रकार)15U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    seed_for_error_vectors,
    Eurydice_array_to_slice_mut_206(&s1_s2));
  Eurydice_arr_8f t0;
  Eurydice_arr_a3 repeat_expression1[8U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t0.तथ्य, repeat_expression1, (माप_प्रकार)8U * माप (Eurydice_arr_a3));
  Eurydice_arr_0f a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[56U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)56U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(a_as_ntt.तथ्य, repeat_expression2, (माप_प्रकार)56U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
    seed_for_a,
    Eurydice_array_to_slice_mut_207(&a_as_ntt));
  Eurydice_arr_bb s1_ntt;
  Eurydice_arr_a3 repeat_expression3[7U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)7U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s1_ntt.तथ्य, repeat_expression3, (माप_प्रकार)7U * माप (Eurydice_arr_a3));
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_208(&s1_ntt),
    Eurydice_array_to_subslice_shared_251(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)0U,
          .end = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A
        }
      )),
    Eurydice_arr_a3);
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)7U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.तथ्य[i0]);
  }
  libcrux_ml_dsa_matrix_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
    Eurydice_array_to_slice_mut_207(&a_as_ntt),
    Eurydice_array_to_slice_shared_206(&s1_ntt),
    Eurydice_array_to_slice_shared_207(&s1_s2),
    Eurydice_array_to_slice_mut_20(&t0));
  Eurydice_arr_8f t1;
  Eurydice_arr_a3 repeat_expression[8U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t1.तथ्य, repeat_expression, (माप_प्रकार)8U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_vector_37(Eurydice_array_to_slice_mut_20(&t0),
    Eurydice_array_to_slice_mut_20(&t1));
  libcrux_ml_dsa_encoding_verification_कुंजी_generate_serialized_37(seed_for_a,
    Eurydice_array_to_slice_shared_200(&t1),
    verification_कुंजी);
  libcrux_ml_dsa_encoding_signing_कुंजी_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_आकार,
    seed_for_a,
    seed_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_slice_u8){
        .ptr = verification_कुंजी.ptr,
        .meta = verification_कुंजी.meta
      }
    ),
    Eurydice_array_to_slice_shared_207(&s1_s2),
    Eurydice_array_to_slice_shared_200(&t0),
    signing_कुंजी);
}

/**
 Generate key pair.
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_generate_कुंजी_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_e2 *signing_कुंजी,
  Eurydice_arr_43 *verification_कुंजी
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_generate_कुंजी_pair_5a(randomness,
    Eurydice_array_to_slice_mut_f7(signing_कुंजी),
    Eurydice_array_to_slice_mut_fc(verification_कुंजी));
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_internal_5a(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(signing_कुंजी,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 remaining_serialized0 = uu____0.snd;
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(remaining_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_SIGNING_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_signing = uu____1.fst;
  Eurydice_borrow_slice_u8 remaining_serialized1 = uu____1.snd;
  Eurydice_borrow_slice_u8_x2
  uu____2 =
    Eurydice_slice_split_at(remaining_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_BYTES_FOR_VERIFICATION_कुंजी_HASH,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 verification_कुंजी_hash = uu____2.fst;
  Eurydice_borrow_slice_u8 remaining_serialized2 = uu____2.snd;
  Eurydice_borrow_slice_u8_x2
  uu____3 =
    Eurydice_slice_split_at(remaining_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_आकार *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_slice_u8 remaining_serialized = uu____3.snd;
  Eurydice_borrow_slice_u8_x2
  uu____4 =
    Eurydice_slice_split_at(remaining_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_आकार *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_slice_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_bb s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[7U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)7U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s1_as_ntt.तथ्य, repeat_expression0, (माप_प्रकार)7U * माप (Eurydice_arr_a3));
  Eurydice_arr_8f s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[8U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(s2_as_ntt.तथ्य, repeat_expression1, (माप_प्रकार)8U * माप (Eurydice_arr_a3));
  Eurydice_arr_8f t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[8U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t0_as_ntt.तथ्य, repeat_expression2, (माप_प्रकार)8U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_आकार,
    s1_serialized,
    Eurydice_array_to_slice_mut_208(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_to_vector_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_आकार,
    s2_serialized,
    Eurydice_array_to_slice_mut_20(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_to_vector_then_ntt_37(t0_serialized,
    Eurydice_array_to_slice_mut_20(&t0_as_ntt));
  Eurydice_arr_0f matrix;
  Eurydice_arr_a3 repeat_expression3[56U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)56U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(matrix.तथ्य, repeat_expression3, (माप_प्रकार)56U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
    seed_for_a,
    Eurydice_array_to_slice_mut_207(&matrix));
  Eurydice_arr_c7 message_representative = { .तथ्य = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(verification_कुंजी_hash,
    &domain_separation_context,
    message,
    &message_representative);
  Eurydice_arr_c7 mask_seed = { .तथ्य = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, seed_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_to_slice_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_to_slice_shared_17(&message_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_to_slice_mut_17(&mask_seed));
  uint16_t domain_separator_for_mask = 0U;
  माप_प्रकार attempt = (माप_प्रकार)0U;
  core_option_Option_b2 commitment_hash0 = { .tag = core_option_None };
  core_option_Option_2d signer_response0 = { .tag = core_option_None };
  core_option_Option_45 hint0 = { .tag = core_option_None };
  जबतक (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_bb mask;
    Eurydice_arr_a3 repeat_expression4[7U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)7U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(mask.तथ्य, repeat_expression4, (माप_प्रकार)7U * माप (Eurydice_arr_a3));
    Eurydice_arr_8f w0;
    Eurydice_arr_a3 repeat_expression5[8U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(w0.तथ्य, repeat_expression5, (माप_प्रकार)8U * माप (Eurydice_arr_a3));
    Eurydice_arr_8f commitment;
    Eurydice_arr_a3 repeat_expression6[8U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(commitment.तथ्य, repeat_expression6, (माप_प्रकार)8U * माप (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_mask_vector_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
      &mask_seed,
      &domain_separator_for_mask,
      Eurydice_array_to_slice_mut_208(&mask));
    Eurydice_arr_8f a_x_mask;
    Eurydice_arr_a3 repeat_expression[8U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
    {
      repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    स_नकल(a_x_mask.तथ्य, repeat_expression, (माप_प्रकार)8U * माप (Eurydice_arr_a3));
    Eurydice_arr_bb
    mask_ntt =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)7U,
        &mask,
        Eurydice_arr_a3,
        Eurydice_arr_bb);
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)7U; i++)
    {
      माप_प्रकार i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&mask_ntt.तथ्य[i0]);
    }
    libcrux_ml_dsa_matrix_compute_matrix_x_mask_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
      Eurydice_array_to_slice_shared_208(&matrix),
      Eurydice_array_to_slice_shared_206(&mask_ntt),
      Eurydice_array_to_slice_mut_20(&a_x_mask));
    libcrux_ml_dsa_arithmetic_decompose_vector_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
      Eurydice_array_to_slice_shared_200(&a_x_mask),
      Eurydice_array_to_slice_mut_20(&w0),
      Eurydice_array_to_slice_mut_20(&commitment));
    Eurydice_arr_c7 commitment_hash_candidate = { .तथ्य = { 0U } };
    Eurydice_arr_1b commitment_serialized = { .तथ्य = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_vector_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_आकार,
      Eurydice_array_to_slice_shared_200(&commitment),
      Eurydice_array_to_slice_mut_68(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_to_slice_shared_17(&message_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_to_slice_shared_68(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_to_slice_mut_17(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_to_slice_shared_17(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_IN_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_bb
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)7U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_bb);
    Eurydice_arr_8f
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)8U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_8f);
    libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_208(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_20(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_matrix_add_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
      Eurydice_array_to_slice_mut_208(&mask),
      Eurydice_array_to_slice_shared_206(&challenge_times_s1));
    libcrux_ml_dsa_matrix_subtract_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
      Eurydice_array_to_slice_mut_20(&w0),
      Eurydice_array_to_slice_shared_200(&challenge_times_s2));
    अगर
    (
      !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_206(&mask),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
    )
    {
      अगर
      (
        !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_200(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
      )
      {
        Eurydice_arr_8f
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)8U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_8f);
        libcrux_ml_dsa_matrix_vector_times_ring_element_37(Eurydice_array_to_slice_mut_20(&challenge_times_t0),
          &verifier_challenge);
        अगर
        (
          !libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_200(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2)
        )
        {
          libcrux_ml_dsa_matrix_add_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
            Eurydice_array_to_slice_mut_20(&w0),
            Eurydice_array_to_slice_shared_200(&challenge_times_t0));
          Eurydice_arr_81
          hint_candidate =
            {
              .तथ्य = {
                { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } },
                { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }
              }
            };
          माप_प्रकार
          ones_in_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_to_slice_shared_200(&w0),
              Eurydice_array_to_slice_shared_200(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
              Eurydice_array_to_slice_mut_861(&hint_candidate));
          अगर (!(ones_in_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_IN_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_b2){
                  .tag = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_2d){ .tag = core_option_Some, .f0 = mask });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_45){
                  .tag = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_परिणाम_परिणाम_53 uu____5;
  अगर (commitment_hash0.tag == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_53){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  अन्यथा
  {
    Eurydice_arr_c7 commitment_hash = commitment_hash0.f0;
    Eurydice_arr_c7 commitment_hash1 = commitment_hash;
    अगर (signer_response0.tag == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_53){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    अन्यथा
    {
      Eurydice_arr_bb signer_response = signer_response0.f0;
      Eurydice_arr_bb signer_response1 = signer_response;
      अगर (!(hint0.tag == core_option_None))
      {
        Eurydice_arr_81 hint = hint0.f0;
        Eurydice_arr_81 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_to_slice_shared_17(&commitment_hash1),
          Eurydice_array_to_slice_shared_206(&signer_response1),
          Eurydice_array_to_slice_shared_861(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_आकार,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_आकार,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_IN_HINT,
          Eurydice_array_to_slice_mut_11(signature));
        वापस (KRML_CLITERAL(core_परिणाम_परिणाम_53){ .tag = core_परिणाम_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_53){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  वापस uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  core_परिणाम_परिणाम_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .tag = core_option_None }));
  अगर (!(uu____0.tag == core_परिणाम_Ok))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_53){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_internal_5a(signing_कुंजी,
      message,
      (
        KRML_CLITERAL(core_option_Option_84){
          .tag = core_option_Some,
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
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_8b
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_5a(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_93 signature = libcrux_ml_dsa_types_zero_c5_f1();
  core_परिणाम_परिणाम_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(signing_कुंजी,
      message,
      context,
      randomness,
      &signature);
  core_परिणाम_परिणाम_8b uu____1;
  अगर (uu____0.tag == core_परिणाम_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_8b){
          .tag = core_परिणाम_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  अन्यथा
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_परिणाम_परिणाम_8b){ .tag = core_परिणाम_Err, .val = { .case_Err = e } });
  }
  वापस uu____1;
}

/**
 Sign.
*/
अटल अंतरभूत core_परिणाम_परिणाम_8b
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign(
  स्थिर Eurydice_arr_e2 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_5a(Eurydice_array_to_slice_shared_f7(signing_कुंजी),
      message,
      context,
      randomness);
}

/**
 Sign.
*/
अटल अंतरभूत core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_mut(
  स्थिर Eurydice_arr_e2 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(Eurydice_array_to_slice_shared_f7(signing_कुंजी),
      message,
      context,
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_mut_3f(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  अगर (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(message, pre_hash_बफर);
    core_परिणाम_परिणाम_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .tag = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    अगर (!(uu____0.tag == core_परिणाम_Ok))
    {
      वापस
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_53){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    वापस
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_internal_5a(signing_कुंजी,
        (
          KRML_CLITERAL(Eurydice_borrow_slice_u8){
            .ptr = pre_hash_बफर.ptr,
            .meta = pre_hash_बफर.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .tag = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  वापस
    (
      KRML_CLITERAL(core_परिणाम_परिणाम_53){
        .tag = core_परिणाम_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_8b
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_3f(
  Eurydice_borrow_slice_u8 signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_93 signature = libcrux_ml_dsa_types_zero_c5_f1();
  core_परिणाम_परिणाम_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_mut_3f(signing_कुंजी,
      message,
      context,
      pre_hash_बफर,
      randomness,
      &signature);
  core_परिणाम_परिणाम_8b uu____1;
  अगर (uu____0.tag == core_परिणाम_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_8b){
          .tag = core_परिणाम_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  अन्यथा
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_परिणाम_परिणाम_8b){ .tag = core_परिणाम_Err, .val = { .case_Err = e } });
  }
  वापस uu____1;
}

/**
 Sign (pre-hashed).
*/
अटल अंतरभूत core_परिणाम_परिणाम_8b
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_pre_hashed_shake128(
  स्थिर Eurydice_arr_e2 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_3f(Eurydice_array_to_slice_shared_f7(signing_कुंजी),
      message,
      context,
      pre_hash_बफर,
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
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_internal_5a(
  स्थिर Eurydice_arr_43 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  core_option_Option_84 domain_separation_context,
  स्थिर Eurydice_arr_93 *signature_serialized
)
{
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_fc(verification_कुंजी),
      LIBCRUX_ML_DSA_CONSTANTS_SEED_FOR_A_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_a = uu____0.fst;
  Eurydice_borrow_slice_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_8f t1;
  Eurydice_arr_a3 repeat_expression0[8U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)8U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(t1.तथ्य, repeat_expression0, (माप_प्रकार)8U * माप (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_कुंजी_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_VERIFICATION_कुंजी_आकार,
    t1_serialized,
    Eurydice_array_to_slice_mut_20(&t1));
  Eurydice_arr_c7 deserialized_commitment_hash = { .तथ्य = { 0U } };
  Eurydice_arr_bb deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[7U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)7U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  स_नकल(deserialized_signer_response.तथ्य,
    repeat_expression1,
    (माप_प्रकार)7U * माप (Eurydice_arr_a3));
  Eurydice_arr_81
  deserialized_hint =
    {
      .तथ्य = {
        { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } },
        { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } }
      }
    };
  core_परिणाम_परिणाम_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_आकार,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_आकार,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_IN_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNATURE_आकार,
      Eurydice_array_to_slice_shared_11(signature_serialized),
      Eurydice_array_to_slice_mut_17(&deserialized_commitment_hash),
      Eurydice_array_to_slice_mut_208(&deserialized_signer_response),
      Eurydice_array_to_slice_mut_861(&deserialized_hint));
  core_परिणाम_परिणाम_41 uu____2;
  अगर (uu____1.tag == core_परिणाम_Ok)
  {
    अगर
    (
      libcrux_ml_dsa_arithmetic_vector_infinity_norm_exceeds_37(Eurydice_array_to_slice_shared_206(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_परिणाम_परिणाम_41){
            .tag = core_परिणाम_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    अन्यथा
    {
      Eurydice_arr_0f matrix;
      Eurydice_arr_a3 repeat_expression[56U];
      क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)56U; i++)
      {
        repeat_expression[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      स_नकल(matrix.तथ्य, repeat_expression, (माप_प्रकार)56U * माप (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_matrix_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
        seed_for_a,
        Eurydice_array_to_slice_mut_207(&matrix));
      Eurydice_arr_c7 verification_कुंजी_hash = { .तथ्य = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_to_slice_shared_fc(verification_कुंजी),
        &verification_कुंजी_hash);
      Eurydice_arr_c7 message_representative = { .तथ्य = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_message_representative_43(Eurydice_array_to_slice_shared_17(&verification_कुंजी_hash),
        &domain_separation_context,
        message,
        &message_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_to_slice_shared_17(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_IN_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)7U; i++)
      {
        माप_प्रकार i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.तथ्य[i0]);
      }
      libcrux_ml_dsa_matrix_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ROWS_IN_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_IN_A,
        Eurydice_array_to_slice_shared_208(&matrix),
        Eurydice_array_to_slice_shared_206(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_to_slice_mut_20(&t1));
      Eurydice_arr_c7 recomputed_commitment_hash = { .तथ्य = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
        Eurydice_array_to_slice_shared_861(&deserialized_hint),
        Eurydice_array_to_slice_mut_20(&t1));
      Eurydice_arr_1b commitment_serialized = { .तथ्य = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_vector_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_आकार,
        Eurydice_array_to_slice_shared_200(&t1),
        Eurydice_array_to_slice_mut_68(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_to_slice_shared_17(&message_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_to_slice_shared_68(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_to_slice_mut_17(&recomputed_commitment_hash));
      अगर
      (
        Eurydice_array_eq((माप_प्रकार)64U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_परिणाम_परिणाम_41){ .tag = core_परिणाम_Ok });
      }
      अन्यथा
      {
        uu____2 =
          (
            KRML_CLITERAL(core_परिणाम_परिणाम_41){
              .tag = core_परिणाम_Err,
              .f0 = libcrux_ml_dsa_types_VerificationError_CommitmentHashesDontMatchError
            }
          );
      }
    }
  }
  अन्यथा
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_परिणाम_परिणाम_41){ .tag = core_परिणाम_Err, .f0 = e });
  }
  वापस uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_5a(
  स्थिर Eurydice_arr_43 *verification_कुंजी_serialized,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_93 *signature_serialized
)
{
  core_परिणाम_परिणाम_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .tag = core_option_None }));
  अगर (!(uu____0.tag == core_परिणाम_Ok))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_41){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_internal_5a(verification_कुंजी_serialized,
      message,
      (
        KRML_CLITERAL(core_option_Option_84){
          .tag = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify(
  स्थिर Eurydice_arr_43 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_93 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_5a(verification_कुंजी,
      message,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
अटल KRML_MUSTINLINE core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_pre_hashed_3f(
  स्थिर Eurydice_arr_43 *verification_कुंजी_serialized,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  स्थिर Eurydice_arr_93 *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(message, pre_hash_बफर);
  core_परिणाम_परिणाम_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .tag = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  अगर (!(uu____0.tag == core_परिणाम_Ok))
  {
    वापस
      (
        KRML_CLITERAL(core_परिणाम_परिणाम_41){
          .tag = core_परिणाम_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_internal_5a(verification_कुंजी_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_slice_u8){
          .ptr = pre_hash_बफर.ptr,
          .meta = pre_hash_बफर.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .tag = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify_pre_hashed_shake128(
  स्थिर Eurydice_arr_43 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_mut_borrow_slice_u8 pre_hash_बफर,
  स्थिर Eurydice_arr_93 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_pre_hashed_3f(verification_कुंजी,
      message,
      context,
      pre_hash_बफर,
      signature);
}

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा libcrux_mldsa_portable_H_DEFINED
#पूर्ण_अगर /* libcrux_mldsa_portable_H */

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


#अगर_अघोषित libcrux_mldsa44_portable_H
#घोषणा libcrux_mldsa44_portable_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


/**
 Generate an ML-DSA-44 Key Pair
*/
अटल अंतरभूत libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_कुंजी_Pair
libcrux_ml_dsa_ml_dsa_44_portable_generate_कुंजी_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_10 signing_कुंजी = { .तथ्य = { 0U } };
  Eurydice_arr_02 verification_कुंजी = { .तथ्य = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_generate_कुंजी_pair(randomness,
    &signing_कुंजी,
    &verification_कुंजी);
  वापस
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_कुंजी_Pair){
        .signing_कुंजी = libcrux_ml_dsa_types_new_9b_ab(signing_कुंजी),
        .verification_कुंजी = libcrux_ml_dsa_types_new_7f_7d(verification_कुंजी)
      }
    );
}

/**
 Generate an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_48
libcrux_ml_dsa_ml_dsa_44_portable_sign(
  स्थिर Eurydice_arr_10 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign(libcrux_ml_dsa_types_as_ref_9b_ab(signing_कुंजी),
      message,
      context,
      randomness);
}

/**
 Generate an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_44_portable_sign_mut(
  स्थिर Eurydice_arr_10 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_mut(libcrux_ml_dsa_types_as_ref_9b_ab(signing_कुंजी),
      message,
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
अटल अंतरभूत core_परिणाम_परिणाम_48
libcrux_ml_dsa_ml_dsa_44_portable_sign_pre_hashed_shake128(
  स्थिर Eurydice_arr_10 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_बफर = { .तथ्य = { 0U } };
  स्थिर Eurydice_arr_10 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_ab(signing_कुंजी);
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_pre_hashed_shake128(uu____0,
      message,
      context,
      Eurydice_array_to_slice_mut_01(&pre_hash_बफर),
      randomness);
}

/**
 Verify an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_44_portable_verify(
  स्थिर Eurydice_arr_02 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_85 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify(libcrux_ml_dsa_types_as_ref_7f_7d(verification_कुंजी),
      message,
      context,
      libcrux_ml_dsa_types_as_ref_c5_37(signature));
}

/**
 Verify a HashML-DSA-44 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_44_portable_verify_pre_hashed_shake128(
  स्थिर Eurydice_arr_02 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_85 *signature
)
{
  Eurydice_arr_ec pre_hash_बफर = { .तथ्य = { 0U } };
  स्थिर Eurydice_arr_02 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_7d(verification_कुंजी);
  Eurydice_borrow_slice_u8 uu____1 = message;
  Eurydice_borrow_slice_u8 uu____2 = context;
  Eurydice_mut_borrow_slice_u8 uu____3 = Eurydice_array_to_slice_mut_01(&pre_hash_बफर);
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_37(signature));
}

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा libcrux_mldsa44_portable_H_DEFINED
#पूर्ण_अगर /* libcrux_mldsa44_portable_H */

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


#अगर_अघोषित libcrux_mldsa65_portable_H
#घोषणा libcrux_mldsa65_portable_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


/**
 Generate an ML-DSA-65 Key Pair
*/
अटल अंतरभूत libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_कुंजी_Pair
libcrux_ml_dsa_ml_dsa_65_portable_generate_कुंजी_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_24 signing_कुंजी = { .तथ्य = { 0U } };
  Eurydice_arr_29 verification_कुंजी = { .तथ्य = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_कुंजी_pair(randomness,
    &signing_कुंजी,
    &verification_कुंजी);
  वापस
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_कुंजी_Pair){
        .signing_कुंजी = libcrux_ml_dsa_types_new_9b_e5(signing_कुंजी),
        .verification_कुंजी = libcrux_ml_dsa_types_new_7f_a2(verification_कुंजी)
      }
    );
}

/**
 Generate an ML-DSA-65 Key Pair
*/
अटल अंतरभूत व्योम
libcrux_ml_dsa_ml_dsa_65_portable_generate_कुंजी_pair_mut(
  Eurydice_arr_ec randomness,
  Eurydice_arr_24 *signing_कुंजी,
  Eurydice_arr_29 *verification_कुंजी
)
{
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_कुंजी_pair(randomness,
    signing_कुंजी,
    verification_कुंजी);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_8c
libcrux_ml_dsa_ml_dsa_65_portable_sign(
  स्थिर Eurydice_arr_24 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(libcrux_ml_dsa_types_as_ref_9b_e5(signing_कुंजी),
      message,
      context,
      randomness);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_65_portable_sign_mut(
  स्थिर Eurydice_arr_24 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(signing_कुंजी,
      message,
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
अटल अंतरभूत core_परिणाम_परिणाम_8c
libcrux_ml_dsa_ml_dsa_65_portable_sign_pre_hashed_shake128(
  स्थिर Eurydice_arr_24 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_बफर = { .तथ्य = { 0U } };
  स्थिर Eurydice_arr_24 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_e5(signing_कुंजी);
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(uu____0,
      message,
      context,
      Eurydice_array_to_slice_mut_01(&pre_hash_बफर),
      randomness);
}

/**
 Verify an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_65_portable_verify(
  स्थिर Eurydice_arr_29 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_0c *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(libcrux_ml_dsa_types_as_ref_7f_a2(verification_कुंजी),
      message,
      context,
      libcrux_ml_dsa_types_as_ref_c5_5c(signature));
}

/**
 Verify a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_65_portable_verify_pre_hashed_shake128(
  स्थिर Eurydice_arr_29 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_0c *signature
)
{
  Eurydice_arr_ec pre_hash_बफर = { .तथ्य = { 0U } };
  स्थिर Eurydice_arr_29 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_a2(verification_कुंजी);
  Eurydice_borrow_slice_u8 uu____1 = message;
  Eurydice_borrow_slice_u8 uu____2 = context;
  Eurydice_mut_borrow_slice_u8 uu____3 = Eurydice_array_to_slice_mut_01(&pre_hash_बफर);
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_5c(signature));
}

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा libcrux_mldsa65_portable_H_DEFINED
#पूर्ण_अगर /* libcrux_mldsa65_portable_H */

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


#अगर_अघोषित libcrux_mldsa87_portable_H
#घोषणा libcrux_mldsa87_portable_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


/**
 Generate an ML-DSA-87 Key Pair
*/
अटल अंतरभूत libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_कुंजी_Pair
libcrux_ml_dsa_ml_dsa_87_portable_generate_कुंजी_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_e2 signing_कुंजी = { .तथ्य = { 0U } };
  Eurydice_arr_43 verification_कुंजी = { .तथ्य = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_generate_कुंजी_pair(randomness,
    &signing_कुंजी,
    &verification_कुंजी);
  वापस
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_कुंजी_Pair){
        .signing_कुंजी = libcrux_ml_dsa_types_new_9b_72(signing_कुंजी),
        .verification_कुंजी = libcrux_ml_dsa_types_new_7f_c6(verification_कुंजी)
      }
    );
}

/**
 Generate an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_8b
libcrux_ml_dsa_ml_dsa_87_portable_sign(
  स्थिर Eurydice_arr_e2 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign(libcrux_ml_dsa_types_as_ref_9b_72(signing_कुंजी),
      message,
      context,
      randomness);
}

/**
 Generate an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_53
libcrux_ml_dsa_ml_dsa_87_portable_sign_mut(
  स्थिर Eurydice_arr_e2 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_mut(libcrux_ml_dsa_types_as_ref_9b_72(signing_कुंजी),
      message,
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
अटल अंतरभूत core_परिणाम_परिणाम_8b
libcrux_ml_dsa_ml_dsa_87_portable_sign_pre_hashed_shake128(
  स्थिर Eurydice_arr_e2 *signing_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_बफर = { .तथ्य = { 0U } };
  स्थिर Eurydice_arr_e2 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_72(signing_कुंजी);
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_pre_hashed_shake128(uu____0,
      message,
      context,
      Eurydice_array_to_slice_mut_01(&pre_hash_बफर),
      randomness);
}

/**
 Verify an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_87_portable_verify(
  स्थिर Eurydice_arr_43 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_93 *signature
)
{
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify(libcrux_ml_dsa_types_as_ref_7f_c6(verification_कुंजी),
      message,
      context,
      libcrux_ml_dsa_types_as_ref_c5_f1(signature));
}

/**
 Verify a HashML-DSA-87 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
अटल अंतरभूत core_परिणाम_परिणाम_41
libcrux_ml_dsa_ml_dsa_87_portable_verify_pre_hashed_shake128(
  स्थिर Eurydice_arr_43 *verification_कुंजी,
  Eurydice_borrow_slice_u8 message,
  Eurydice_borrow_slice_u8 context,
  स्थिर Eurydice_arr_93 *signature
)
{
  Eurydice_arr_ec pre_hash_बफर = { .तथ्य = { 0U } };
  स्थिर Eurydice_arr_43 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_c6(verification_कुंजी);
  Eurydice_borrow_slice_u8 uu____1 = message;
  Eurydice_borrow_slice_u8 uu____2 = context;
  Eurydice_mut_borrow_slice_u8 uu____3 = Eurydice_array_to_slice_mut_01(&pre_hash_बफर);
  वापस
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_f1(signature));
}

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा libcrux_mldsa87_portable_H_DEFINED
#पूर्ण_अगर /* libcrux_mldsa87_portable_H */

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


#अगर_अघोषित libcrux_mlkem768_portable_H
#घोषणा libcrux_mlkem768_portable_H



#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


अटल अंतरभूत Eurydice_arr_c7
libcrux_ml_kem_hash_functions_portable_G(Eurydice_borrow_slice_u8 निवेश)
{
  Eurydice_arr_c7 digest = { .तथ्य = { 0U } };
  libcrux_sha3_portable_sha512(Eurydice_array_to_slice_mut_17(&digest), निवेश);
  वापस digest;
}

अटल अंतरभूत Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_H(Eurydice_borrow_slice_u8 निवेश)
{
  Eurydice_arr_ec digest = { .तथ्य = { 0U } };
  libcrux_sha3_portable_sha256(Eurydice_array_to_slice_mut_01(&digest), निवेश);
  वापस digest;
}

#घोषणा LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R ((KRML_CLITERAL(Eurydice_arr_34){ .तथ्य = { -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468, 573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571, 1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275, -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097, 603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185, -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628 } }))

अटल KRML_MUSTINLINE int16_t libcrux_ml_kem_polynomial_zeta(माप_प्रकार i)
{
  वापस LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R.तथ्य[i];
}

#घोषणा LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT ((माप_प्रकार)16U)

#घोषणा LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR ((माप_प्रकार)16U)

#घोषणा LIBCRUX_ML_KEM_VECTOR_TRAITS_MONTGOMERY_R_SQUARED_MOD_FIELD_MODULUS (1353)

#घोषणा LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS (3329)

#घोषणा LIBCRUX_ML_KEM_VECTOR_TRAITS_INVERSE_OF_MODULUS_MOD_MONTGOMERY_R (62209U)

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_vector_type_from_i16_array(Eurydice_borrow_slice_i16 array)
{
  Eurydice_arr_d6 arr;
  स_नकल(arr.तथ्य,
    Eurydice_slice_subslice_shared_a6(array,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)16U })).ptr,
    (माप_प्रकार)16U * माप (int16_t));
  वापस
    core_परिणाम_unwrap_26_d3((
        KRML_CLITERAL(core_परिणाम_परिणाम_ec){ .tag = core_परिणाम_Ok, .val = { .case_Ok = arr } }
      ));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_from_i16_array_b8(Eurydice_borrow_slice_i16 array)
{
  वापस
    libcrux_ml_kem_vector_portable_vector_type_from_i16_array(libcrux_secrets_int_classify_public_classify_ref_6d_39(array));
}

अटल KRML_MUSTINLINE Eurydice_arr_d6 libcrux_ml_kem_vector_portable_vector_type_zero(व्योम)
{
  वापस
    libcrux_secrets_int_public_integers_classify_27_4b((
        KRML_CLITERAL(Eurydice_arr_d6){ .तथ्य = { 0U } }
      ));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6 libcrux_ml_kem_vector_portable_ZERO_b8(व्योम)
{
  वापस libcrux_ml_kem_vector_portable_vector_type_zero();
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_arithmetic_add(Eurydice_arr_d6 lhs, स्थिर Eurydice_arr_d6 *rhs)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार uu____0 = i0;
    lhs.तथ्य[uu____0] += rhs->तथ्य[i0];
  }
  वापस lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_add_b8(Eurydice_arr_d6 lhs, स्थिर Eurydice_arr_d6 *rhs)
{
  वापस libcrux_ml_kem_vector_portable_arithmetic_add(lhs, rhs);
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_arithmetic_sub(Eurydice_arr_d6 lhs, स्थिर Eurydice_arr_d6 *rhs)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार uu____0 = i0;
    lhs.तथ्य[uu____0] -= rhs->तथ्य[i0];
  }
  वापस lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_sub_b8(Eurydice_arr_d6 lhs, स्थिर Eurydice_arr_d6 *rhs)
{
  वापस libcrux_ml_kem_vector_portable_arithmetic_sub(lhs, rhs);
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_arithmetic_multiply_by_constant(Eurydice_arr_d6 vec, int16_t c)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार uu____0 = i0;
    vec.तथ्य[uu____0] *= c;
  }
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_multiply_by_constant_b8(Eurydice_arr_d6 vec, int16_t c)
{
  वापस libcrux_ml_kem_vector_portable_arithmetic_multiply_by_constant(vec, c);
}

/**
 Note: This function is not secret independent
 Only use with public values.
*/
अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_arithmetic_cond_subtract_3329(Eurydice_arr_d6 vec)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    अगर (libcrux_secrets_int_public_integers_declassify_d8_39(vec.तथ्य[i0]) >= 3329)
    {
      माप_प्रकार uu____0 = i0;
      vec.तथ्य[uu____0] -= 3329;
    }
  }
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_cond_subtract_3329_b8(Eurydice_arr_d6 v)
{
  वापस libcrux_ml_kem_vector_portable_arithmetic_cond_subtract_3329(v);
}

#घोषणा LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER (20159)

#घोषणा LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_SHIFT (26)

#घोषणा LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_R ((int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_SHIFT))

/**
 Signed Barrett Reduction

 Given an input `value`, `barrett_reduce` outputs a representative `result`
 such that:

 - result ≡ value (mod FIELD_MODULUS)
 - the absolute value of `result` is bound as follows:

 `|result| ≤ FIELD_MODULUS / 2 · (|value|/BARRETT_R + 1)

 Note: The input bound is 28296 to prevent overflow in the multiplication of quotient by FIELD_MODULUS

*/
अटल अंतरभूत int16_t
libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce_element(int16_t मूल्य)
{
  int32_t
  t =
    libcrux_secrets_int_as_i32_f5(मूल्य) *
      LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER
    + (LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_R >> 1U);
  int16_t
  quotient =
    libcrux_secrets_int_as_i16_36(t >> (uint32_t)LIBCRUX_ML_KEM_VECTOR_TRAITS_BARRETT_SHIFT);
  वापस मूल्य - quotient * LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS;
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce(Eurydice_arr_d6 vec)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    int16_t vi = libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce_element(vec.तथ्य[i0]);
    vec.तथ्य[i0] = vi;
  }
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_barrett_reduce_b8(Eurydice_arr_d6 vector)
{
  वापस libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce(vector);
}

#घोषणा LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT (16U)

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
अटल अंतरभूत int16_t
libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(int32_t मूल्य)
{
  int32_t
  k =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(मूल्य)) *
      libcrux_secrets_int_as_i32_b8(libcrux_secrets_int_public_integers_classify_27_df(LIBCRUX_ML_KEM_VECTOR_TRAITS_INVERSE_OF_MODULUS_MOD_MONTGOMERY_R));
  int32_t
  k_times_modulus =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(k)) *
      libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_public_integers_classify_27_39(LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS));
  int16_t
  c =
    libcrux_secrets_int_as_i16_36(k_times_modulus >>
        (uint32_t)LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT);
  int16_t
  मूल्य_ऊपरी =
    libcrux_secrets_int_as_i16_36(मूल्य >>
        (uint32_t)LIBCRUX_ML_KEM_VECTOR_PORTABLE_ARITHMETIC_MONTGOMERY_SHIFT);
  वापस मूल्य_ऊपरी - c;
}

/**
 If `fe` is some field element 'x' of the Kyber field and `fer` is congruent to
 `y · MONTGOMERY_R`, this procedure outputs a value that is congruent to
 `x · y`, as follows:

    `fe · fer ≡ x · y · MONTGOMERY_R (mod FIELD_MODULUS)`

 `montgomery_reduce` takes the value `x · y · MONTGOMERY_R` and outputs a representative
 `x · y · MONTGOMERY_R * MONTGOMERY_R^{-1} ≡ x · y (mod FIELD_MODULUS)`.
*/
अटल KRML_MUSTINLINE int16_t
libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_fe_by_fer(
  int16_t fe,
  int16_t fer
)
{
  int32_t product = libcrux_secrets_int_as_i32_f5(fe) * libcrux_secrets_int_as_i32_f5(fer);
  वापस libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(product);
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_d6 vec,
  int16_t c
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    vec.तथ्य[i0] =
      libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_fe_by_fer(vec.तथ्य[i0],
        c);
  }
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(
  Eurydice_arr_d6 vector,
  int16_t constant
)
{
  वापस
    libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_by_constant(vector,
      libcrux_secrets_int_public_integers_classify_27_39(constant));
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_arithmetic_bitwise_and_with_constant(
  Eurydice_arr_d6 vec,
  int16_t c
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    माप_प्रकार uu____0 = i0;
    vec.तथ्य[uu____0] &= c;
  }
  वापस vec;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.arithmetic.shift_right
with const generics
- SHIFT_BY= 15
*/
अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_arithmetic_shift_दायाँ_ef(Eurydice_arr_d6 vec)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    vec.तथ्य[i0] >>= (uint32_t)15;
  }
  वापस vec;
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_arithmetic_to_unsigned_representative(Eurydice_arr_d6 a)
{
  Eurydice_arr_d6 t = libcrux_ml_kem_vector_portable_arithmetic_shift_दायाँ_ef(a);
  Eurydice_arr_d6
  fm =
    libcrux_ml_kem_vector_portable_arithmetic_bitwise_and_with_constant(t,
      LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS);
  वापस libcrux_ml_kem_vector_portable_arithmetic_add(a, &fm);
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_to_unsigned_representative_b8(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_arithmetic_to_unsigned_representative(a);
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
अटल अंतरभूत uint8_t
libcrux_ml_kem_vector_portable_compress_compress_message_coefficient(uint16_t fe)
{
  int16_t
  shifted =
    libcrux_secrets_int_public_integers_classify_27_39(1664) - libcrux_secrets_int_as_i16_ca(fe);
  int16_t mask = shifted >> 15U;
  int16_t shifted_to_positive = mask ^ shifted;
  int16_t shifted_positive_in_range = shifted_to_positive - 832;
  int16_t r0 = shifted_positive_in_range >> 15U;
  int16_t r1 = r0 & 1;
  वापस libcrux_secrets_int_as_u8_f5(r1);
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_compress_compress_1(Eurydice_arr_d6 a)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    a.तथ्य[i0] =
      libcrux_secrets_int_as_i16_59(libcrux_ml_kem_vector_portable_compress_compress_message_coefficient(libcrux_secrets_int_as_u16_f5(a.तथ्य[i0])));
  }
  वापस a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6 libcrux_ml_kem_vector_portable_compress_1_b8(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_compress_compress_1(a);
}

अटल KRML_MUSTINLINE uint32_t
libcrux_ml_kem_vector_portable_arithmetic_get_n_least_significant_bits(
  uint8_t n,
  uint32_t मूल्य
)
{
  वापस मूल्य & ((1U << (uint32_t)n) - 1U);
}

अटल अंतरभूत int16_t
libcrux_ml_kem_vector_portable_compress_compress_ciphertext_coefficient(
  uint8_t coefficient_bits,
  uint16_t fe
)
{
  uint64_t compressed = libcrux_secrets_int_as_u64_ca(fe) << (uint32_t)coefficient_bits;
  compressed += 1664ULL;
  compressed *= 10321340ULL;
  compressed >>= 35U;
  वापस
    libcrux_secrets_int_as_i16_b8(libcrux_ml_kem_vector_portable_arithmetic_get_n_least_significant_bits(coefficient_bits,
        libcrux_secrets_int_as_u32_a3(compressed)));
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_compress_decompress_1(Eurydice_arr_d6 a)
{
  Eurydice_arr_d6 z = libcrux_ml_kem_vector_portable_vector_type_zero();
  Eurydice_arr_d6 s = libcrux_ml_kem_vector_portable_arithmetic_sub(z, &a);
  Eurydice_arr_d6
  res = libcrux_ml_kem_vector_portable_arithmetic_bitwise_and_with_constant(s, 1665);
  वापस res;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6 libcrux_ml_kem_vector_portable_decompress_1_b8(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_compress_decompress_1(a);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_vector_portable_ntt_ntt_step(
  Eurydice_arr_d6 *vec,
  int16_t zeta,
  माप_प्रकार i,
  माप_प्रकार j
)
{
  int16_t
  t =
    libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_fe_by_fer(vec->तथ्य[j],
      libcrux_secrets_int_public_integers_classify_27_39(zeta));
  int16_t a_minus_t = vec->तथ्य[i] - t;
  int16_t a_plus_t = vec->तथ्य[i] + t;
  vec->तथ्य[j] = a_minus_t;
  vec->तथ्य[i] = a_plus_t;
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_ntt_layer_1_step(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (माप_प्रकार)0U, (माप_प्रकार)2U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (माप_प्रकार)1U, (माप_प्रकार)3U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (माप_प्रकार)4U, (माप_प्रकार)6U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (माप_प्रकार)5U, (माप_प्रकार)7U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta2, (माप_प्रकार)8U, (माप_प्रकार)10U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta2, (माप_प्रकार)9U, (माप_प्रकार)11U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta3, (माप_प्रकार)12U, (माप_प्रकार)14U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta3, (माप_प्रकार)13U, (माप_प्रकार)15U);
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_layer_1_step_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  वापस libcrux_ml_kem_vector_portable_ntt_ntt_layer_1_step(a, zeta0, zeta1, zeta2, zeta3);
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_ntt_layer_2_step(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (माप_प्रकार)0U, (माप_प्रकार)4U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (माप_प्रकार)1U, (माप_प्रकार)5U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (माप_प्रकार)2U, (माप_प्रकार)6U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta0, (माप_प्रकार)3U, (माप_प्रकार)7U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (माप_प्रकार)8U, (माप_प्रकार)12U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (माप_प्रकार)9U, (माप_प्रकार)13U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (माप_प्रकार)10U, (माप_प्रकार)14U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta1, (माप_प्रकार)11U, (माप_प्रकार)15U);
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_layer_2_step_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  वापस libcrux_ml_kem_vector_portable_ntt_ntt_layer_2_step(a, zeta0, zeta1);
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_ntt_layer_3_step(Eurydice_arr_d6 vec, int16_t zeta)
{
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (माप_प्रकार)0U, (माप_प्रकार)8U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (माप_प्रकार)1U, (माप_प्रकार)9U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (माप_प्रकार)2U, (माप_प्रकार)10U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (माप_प्रकार)3U, (माप_प्रकार)11U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (माप_प्रकार)4U, (माप_प्रकार)12U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (माप_प्रकार)5U, (माप_प्रकार)13U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (माप_प्रकार)6U, (माप_प्रकार)14U);
  libcrux_ml_kem_vector_portable_ntt_ntt_step(&vec, zeta, (माप_प्रकार)7U, (माप_प्रकार)15U);
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_layer_3_step_b8(Eurydice_arr_d6 a, int16_t zeta)
{
  वापस libcrux_ml_kem_vector_portable_ntt_ntt_layer_3_step(a, zeta);
}

अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(
  Eurydice_arr_d6 *vec,
  int16_t zeta,
  माप_प्रकार i,
  माप_प्रकार j
)
{
  int16_t a_minus_b = vec->तथ्य[j] - vec->तथ्य[i];
  int16_t a_plus_b = vec->तथ्य[j] + vec->तथ्य[i];
  int16_t o0 = libcrux_ml_kem_vector_portable_arithmetic_barrett_reduce_element(a_plus_b);
  int16_t
  o1 =
    libcrux_ml_kem_vector_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      libcrux_secrets_int_public_integers_classify_27_39(zeta));
  vec->तथ्य[i] = o0;
  vec->तथ्य[j] = o1;
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_1_step(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (माप_प्रकार)0U, (माप_प्रकार)2U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (माप_प्रकार)1U, (माप_प्रकार)3U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (माप_प्रकार)4U, (माप_प्रकार)6U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (माप_प्रकार)5U, (माप_प्रकार)7U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta2, (माप_प्रकार)8U, (माप_प्रकार)10U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta2, (माप_प्रकार)9U, (माप_प्रकार)11U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta3, (माप_प्रकार)12U, (माप_प्रकार)14U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta3, (माप_प्रकार)13U, (माप_प्रकार)15U);
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_inv_ntt_layer_1_step_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  वापस libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_1_step(a, zeta0, zeta1, zeta2, zeta3);
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_2_step(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (माप_प्रकार)0U, (माप_प्रकार)4U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (माप_प्रकार)1U, (माप_प्रकार)5U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (माप_प्रकार)2U, (माप_प्रकार)6U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta0, (माप_प्रकार)3U, (माप_प्रकार)7U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (माप_प्रकार)8U, (माप_प्रकार)12U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (माप_प्रकार)9U, (माप_प्रकार)13U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (माप_प्रकार)10U, (माप_प्रकार)14U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta1, (माप_प्रकार)11U, (माप_प्रकार)15U);
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_inv_ntt_layer_2_step_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  वापस libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_2_step(a, zeta0, zeta1);
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_3_step(Eurydice_arr_d6 vec, int16_t zeta)
{
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (माप_प्रकार)0U, (माप_प्रकार)8U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (माप_प्रकार)1U, (माप_प्रकार)9U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (माप_प्रकार)2U, (माप_प्रकार)10U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (माप_प्रकार)3U, (माप_प्रकार)11U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (माप_प्रकार)4U, (माप_प्रकार)12U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (माप_प्रकार)5U, (माप_प्रकार)13U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (माप_प्रकार)6U, (माप_प्रकार)14U);
  libcrux_ml_kem_vector_portable_ntt_inv_ntt_step(&vec, zeta, (माप_प्रकार)7U, (माप_प्रकार)15U);
  वापस vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_inv_ntt_layer_3_step_b8(Eurydice_arr_d6 a, int16_t zeta)
{
  वापस libcrux_ml_kem_vector_portable_ntt_inv_ntt_layer_3_step(a, zeta);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(
  स्थिर Eurydice_arr_d6 *a,
  स्थिर Eurydice_arr_d6 *b,
  int16_t zeta,
  माप_प्रकार i,
  Eurydice_arr_d6 *out
)
{
  int16_t ai = a->तथ्य[(माप_प्रकार)2U * i];
  int16_t bi = b->तथ्य[(माप_प्रकार)2U * i];
  int16_t aj = a->तथ्य[(माप_प्रकार)2U * i + (माप_प्रकार)1U];
  int16_t bj = b->तथ्य[(माप_प्रकार)2U * i + (माप_प्रकार)1U];
  int32_t ai_bi = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t aj_bj_ = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bj);
  int16_t aj_bj = libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(aj_bj_);
  int32_t
  aj_bj_zeta = libcrux_secrets_int_as_i32_f5(aj_bj) * libcrux_secrets_int_as_i32_f5(zeta);
  int32_t ai_bi_aj_bj = ai_bi + aj_bj_zeta;
  int16_t o0 = libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(ai_bi_aj_bj);
  int32_t ai_bj = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bj);
  int32_t aj_bi = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t ai_bj_aj_bi = ai_bj + aj_bi;
  int16_t o1 = libcrux_ml_kem_vector_portable_arithmetic_montgomery_reduce_element(ai_bj_aj_bi);
  out->तथ्य[(माप_प्रकार)2U * i] = o0;
  out->तथ्य[(माप_प्रकार)2U * i + (माप_प्रकार)1U] = o1;
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_ntt_multiply(
  स्थिर Eurydice_arr_d6 *lhs,
  स्थिर Eurydice_arr_d6 *rhs,
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
  Eurydice_arr_d6 out = libcrux_ml_kem_vector_portable_vector_type_zero();
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(zeta0),
    (माप_प्रकार)0U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(nzeta0),
    (माप_प्रकार)1U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(zeta1),
    (माप_प्रकार)2U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(nzeta1),
    (माप_प्रकार)3U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(zeta2),
    (माप_प्रकार)4U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(nzeta2),
    (माप_प्रकार)5U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(zeta3),
    (माप_प्रकार)6U,
    &out);
  libcrux_ml_kem_vector_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_public_integers_classify_27_39(nzeta3),
    (माप_प्रकार)7U,
    &out);
  वापस out;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_ntt_multiply_b8(
  स्थिर Eurydice_arr_d6 *lhs,
  स्थिर Eurydice_arr_d6 *rhs,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  वापस libcrux_ml_kem_vector_portable_ntt_ntt_multiply(lhs, rhs, zeta0, zeta1, zeta2, zeta3);
}

अटल KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_ml_kem_vector_portable_serialize_serialize_1(Eurydice_arr_d6 v)
{
  uint8_t
  result0 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[0U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[1U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[2U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[3U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[4U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[5U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[6U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[7U]) << 7U;
  uint8_t
  result1 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[8U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[9U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[10U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[11U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[12U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[13U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[14U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.तथ्य[15U]) << 7U;
  वापस (KRML_CLITERAL(Eurydice_array_u8x2){ .तथ्य = { result0, result1 } });
}

अटल अंतरभूत Eurydice_array_u8x2 libcrux_ml_kem_vector_portable_serialize_1(Eurydice_arr_d6 a)
{
  वापस
    libcrux_secrets_int_public_integers_declassify_d8_75(libcrux_ml_kem_vector_portable_serialize_serialize_1(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_array_u8x2
libcrux_ml_kem_vector_portable_serialize_1_b8(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_serialize_1(a);
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_serialize_deserialize_1(Eurydice_borrow_slice_u8 v)
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
  वापस
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .तथ्य = {
          result0, result1, result2, result3, result4, result5, result6, result7, result8, result9,
          result10, result11, result12, result13, result14, result15
        }
      }
    );
}

अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_deserialize_1(Eurydice_borrow_slice_u8 a)
{
  वापस
    libcrux_ml_kem_vector_portable_serialize_deserialize_1(libcrux_secrets_int_classify_public_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_deserialize_1_b8(Eurydice_borrow_slice_u8 a)
{
  वापस libcrux_ml_kem_vector_portable_deserialize_1(a);
}

अटल KRML_MUSTINLINE uint8_t_x4
libcrux_ml_kem_vector_portable_serialize_serialize_4_int(Eurydice_borrow_slice_i16 v)
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
  वापस
    (KRML_CLITERAL(uint8_t_x4){ .fst = result0, .snd = result1, .thd = result2, .f3 = result3 });
}

अटल KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_ml_kem_vector_portable_serialize_serialize_4(Eurydice_arr_d6 v)
{
  uint8_t_x4
  result0_3 =
    libcrux_ml_kem_vector_portable_serialize_serialize_4_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)8U })));
  uint8_t_x4
  result4_7 =
    libcrux_ml_kem_vector_portable_serialize_serialize_4_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)8U, .end = (माप_प्रकार)16U })));
  वापस
    (
      KRML_CLITERAL(Eurydice_array_u8x8){
        .तथ्य = {
          result0_3.fst, result0_3.snd, result0_3.thd, result0_3.f3, result4_7.fst, result4_7.snd,
          result4_7.thd, result4_7.f3
        }
      }
    );
}

अटल अंतरभूत Eurydice_array_u8x8 libcrux_ml_kem_vector_portable_serialize_4(Eurydice_arr_d6 a)
{
  वापस
    libcrux_secrets_int_public_integers_declassify_d8_52(libcrux_ml_kem_vector_portable_serialize_serialize_4(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_array_u8x8
libcrux_ml_kem_vector_portable_serialize_4_b8(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_serialize_4(a);
}

अटल KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_vector_portable_serialize_deserialize_4_int(Eurydice_borrow_slice_u8 bytes)
{
  int16_t v0 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[0U] & 15U);
  int16_t v1 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[0U] >> 4U & 15U);
  int16_t v2 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[1U] & 15U);
  int16_t v3 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[1U] >> 4U & 15U);
  int16_t v4 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[2U] & 15U);
  int16_t v5 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[2U] >> 4U & 15U);
  int16_t v6 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[3U] & 15U);
  int16_t v7 = libcrux_secrets_int_as_i16_59((uint32_t)bytes.ptr[3U] >> 4U & 15U);
  वापस
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

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_serialize_deserialize_4(Eurydice_borrow_slice_u8 bytes)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_4_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)4U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_4_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)4U, .end = (माप_प्रकार)8U })));
  वापस
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .तथ्य = {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_deserialize_4(Eurydice_borrow_slice_u8 a)
{
  वापस
    libcrux_ml_kem_vector_portable_serialize_deserialize_4(libcrux_secrets_int_classify_public_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_deserialize_4_b8(Eurydice_borrow_slice_u8 a)
{
  वापस libcrux_ml_kem_vector_portable_deserialize_4(a);
}

अटल KRML_MUSTINLINE uint8_t_x5
libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_borrow_slice_i16 v)
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
  वापस (KRML_CLITERAL(uint8_t_x5){ .fst = r0, .snd = r1, .thd = r2, .f3 = r3, .f4 = r4 });
}

अटल KRML_MUSTINLINE Eurydice_arr_fc
libcrux_ml_kem_vector_portable_serialize_serialize_10(Eurydice_arr_d6 v)
{
  uint8_t_x5
  r0_4 =
    libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)4U })));
  uint8_t_x5
  r5_9 =
    libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)4U, .end = (माप_प्रकार)8U })));
  uint8_t_x5
  r10_14 =
    libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)8U, .end = (माप_प्रकार)12U })));
  uint8_t_x5
  r15_19 =
    libcrux_ml_kem_vector_portable_serialize_serialize_10_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)12U, .end = (माप_प्रकार)16U })));
  वापस
    (
      KRML_CLITERAL(Eurydice_arr_fc){
        .तथ्य = {
          r0_4.fst, r0_4.snd, r0_4.thd, r0_4.f3, r0_4.f4, r5_9.fst, r5_9.snd, r5_9.thd, r5_9.f3,
          r5_9.f4, r10_14.fst, r10_14.snd, r10_14.thd, r10_14.f3, r10_14.f4, r15_19.fst, r15_19.snd,
          r15_19.thd, r15_19.f3, r15_19.f4
        }
      }
    );
}

अटल अंतरभूत Eurydice_arr_fc libcrux_ml_kem_vector_portable_serialize_10(Eurydice_arr_d6 a)
{
  वापस
    libcrux_secrets_int_public_integers_declassify_d8_2b(libcrux_ml_kem_vector_portable_serialize_serialize_10(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_fc libcrux_ml_kem_vector_portable_serialize_10_b8(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_serialize_10(a);
}

अटल KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_vector_portable_serialize_deserialize_10_int(Eurydice_borrow_slice_u8 bytes)
{
  int16_t
  r0 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(bytes.ptr[1U])
      & 3)
      << 8U)
      | (libcrux_secrets_int_as_i16_59(bytes.ptr[0U]) & 255));
  int16_t
  r1 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(bytes.ptr[2U])
      & 15)
      << 6U)
      | libcrux_secrets_int_as_i16_59(bytes.ptr[1U]) >> 2U);
  int16_t
  r2 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(bytes.ptr[3U])
      & 63)
      << 4U)
      | libcrux_secrets_int_as_i16_59(bytes.ptr[2U]) >> 4U);
  int16_t
  r3 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)libcrux_secrets_int_as_i16_59(bytes.ptr[4U])
      << 2U)
      | libcrux_secrets_int_as_i16_59(bytes.ptr[3U]) >> 6U);
  int16_t
  r4 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(bytes.ptr[6U])
      & 3)
      << 8U)
      | (libcrux_secrets_int_as_i16_59(bytes.ptr[5U]) & 255));
  int16_t
  r5 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(bytes.ptr[7U])
      & 15)
      << 6U)
      | libcrux_secrets_int_as_i16_59(bytes.ptr[6U]) >> 2U);
  int16_t
  r6 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(bytes.ptr[8U])
      & 63)
      << 4U)
      | libcrux_secrets_int_as_i16_59(bytes.ptr[7U]) >> 4U);
  int16_t
  r7 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)libcrux_secrets_int_as_i16_59(bytes.ptr[9U])
      << 2U)
      | libcrux_secrets_int_as_i16_59(bytes.ptr[8U]) >> 6U);
  वापस
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

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_serialize_deserialize_10(Eurydice_borrow_slice_u8 bytes)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_10_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)10U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_10_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)10U, .end = (माप_प्रकार)20U })));
  वापस
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .तथ्य = {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_deserialize_10(Eurydice_borrow_slice_u8 a)
{
  वापस
    libcrux_ml_kem_vector_portable_serialize_deserialize_10(libcrux_secrets_int_classify_public_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_deserialize_10_b8(Eurydice_borrow_slice_u8 a)
{
  वापस libcrux_ml_kem_vector_portable_deserialize_10(a);
}

अटल KRML_MUSTINLINE uint8_t_x3
libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_borrow_slice_i16 v)
{
  uint8_t r0 = libcrux_secrets_int_as_u8_f5(v.ptr[0U] & 255);
  uint8_t
  r1 =
    libcrux_secrets_int_as_u8_f5(v.ptr[0U] >> 8U | (int16_t)((uint32_t)(v.ptr[1U] & 15) << 4U));
  uint8_t r2 = libcrux_secrets_int_as_u8_f5(v.ptr[1U] >> 4U & 255);
  वापस (KRML_CLITERAL(uint8_t_x3){ .fst = r0, .snd = r1, .thd = r2 });
}

अटल KRML_MUSTINLINE Eurydice_arr_94
libcrux_ml_kem_vector_portable_serialize_serialize_12(Eurydice_arr_d6 v)
{
  uint8_t_x3
  r0_2 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)2U })));
  uint8_t_x3
  r3_5 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)2U, .end = (माप_प्रकार)4U })));
  uint8_t_x3
  r6_8 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)4U, .end = (माप_प्रकार)6U })));
  uint8_t_x3
  r9_11 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)6U, .end = (माप_प्रकार)8U })));
  uint8_t_x3
  r12_14 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)8U, .end = (माप_प्रकार)10U })));
  uint8_t_x3
  r15_17 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)10U, .end = (माप_प्रकार)12U })));
  uint8_t_x3
  r18_20 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)12U, .end = (माप_प्रकार)14U })));
  uint8_t_x3
  r21_23 =
    libcrux_ml_kem_vector_portable_serialize_serialize_12_int(Eurydice_array_to_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)14U, .end = (माप_प्रकार)16U })));
  वापस
    (
      KRML_CLITERAL(Eurydice_arr_94){
        .तथ्य = {
          r0_2.fst, r0_2.snd, r0_2.thd, r3_5.fst, r3_5.snd, r3_5.thd, r6_8.fst, r6_8.snd, r6_8.thd,
          r9_11.fst, r9_11.snd, r9_11.thd, r12_14.fst, r12_14.snd, r12_14.thd, r15_17.fst,
          r15_17.snd, r15_17.thd, r18_20.fst, r18_20.snd, r18_20.thd, r21_23.fst, r21_23.snd,
          r21_23.thd
        }
      }
    );
}

अटल अंतरभूत Eurydice_arr_94 libcrux_ml_kem_vector_portable_serialize_12(Eurydice_arr_d6 a)
{
  वापस
    libcrux_secrets_int_public_integers_declassify_d8_40(libcrux_ml_kem_vector_portable_serialize_serialize_12(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_94 libcrux_ml_kem_vector_portable_serialize_12_b8(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_serialize_12(a);
}

अटल KRML_MUSTINLINE int16_t_x2
libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_borrow_slice_u8 bytes)
{
  int16_t byte0 = libcrux_secrets_int_as_i16_59(bytes.ptr[0U]);
  int16_t byte1 = libcrux_secrets_int_as_i16_59(bytes.ptr[1U]);
  int16_t byte2 = libcrux_secrets_int_as_i16_59(bytes.ptr[2U]);
  int16_t r0 = (int16_t)((uint32_t)(byte1 & 15) << 8U) | (byte0 & 255);
  int16_t r1 = (int16_t)((uint32_t)byte2 << 4U) | (byte1 >> 4U & 15);
  वापस (KRML_CLITERAL(int16_t_x2){ .fst = r0, .snd = r1 });
}

अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_serialize_deserialize_12(Eurydice_borrow_slice_u8 bytes)
{
  int16_t_x2
  v0_1 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)3U })));
  int16_t_x2
  v2_3 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)3U, .end = (माप_प्रकार)6U })));
  int16_t_x2
  v4_5 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)6U, .end = (माप_प्रकार)9U })));
  int16_t_x2
  v6_7 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)9U, .end = (माप_प्रकार)12U })));
  int16_t_x2
  v8_9 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)12U, .end = (माप_प्रकार)15U })));
  int16_t_x2
  v10_11 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)15U, .end = (माप_प्रकार)18U })));
  int16_t_x2
  v12_13 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)18U, .end = (माप_प्रकार)21U })));
  int16_t_x2
  v14_15 =
    libcrux_ml_kem_vector_portable_serialize_deserialize_12_int(Eurydice_slice_subslice_shared_c8(bytes,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)21U, .end = (माप_प्रकार)24U })));
  वापस
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .तथ्य = {
          v0_1.fst, v0_1.snd, v2_3.fst, v2_3.snd, v4_5.fst, v4_5.snd, v6_7.fst, v6_7.snd, v8_9.fst,
          v8_9.snd, v10_11.fst, v10_11.snd, v12_13.fst, v12_13.snd, v14_15.fst, v14_15.snd
        }
      }
    );
}

अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_deserialize_12(Eurydice_borrow_slice_u8 a)
{
  वापस
    libcrux_ml_kem_vector_portable_serialize_deserialize_12(libcrux_secrets_int_classify_public_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_deserialize_12_b8(Eurydice_borrow_slice_u8 a)
{
  वापस libcrux_ml_kem_vector_portable_deserialize_12(a);
}

अटल KRML_MUSTINLINE माप_प्रकार
libcrux_ml_kem_vector_portable_sampling_rej_sample(
  Eurydice_borrow_slice_u8 a,
  Eurydice_mut_borrow_slice_i16 परिणाम
)
{
  माप_प्रकार sampled = (माप_प्रकार)0U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < a.meta / (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    int16_t b1 = (int16_t)(uint32_t)a.ptr[i0 * (माप_प्रकार)3U + (माप_प्रकार)0U];
    int16_t b2 = (int16_t)(uint32_t)a.ptr[i0 * (माप_प्रकार)3U + (माप_प्रकार)1U];
    int16_t b3 = (int16_t)(uint32_t)a.ptr[i0 * (माप_प्रकार)3U + (माप_प्रकार)2U];
    int16_t d1 = (int16_t)((uint32_t)(b2 & 15) << 8U) | b1;
    int16_t d2 = (int16_t)((uint32_t)b3 << 4U) | b2 >> 4U;
    अगर (d1 < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS)
    {
      अगर (sampled < (माप_प्रकार)16U)
      {
        परिणाम.ptr[sampled] = d1;
        sampled++;
      }
    }
    अगर (d2 < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS)
    {
      अगर (sampled < (माप_प्रकार)16U)
      {
        परिणाम.ptr[sampled] = d2;
        sampled++;
      }
    }
  }
  वापस sampled;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
अटल अंतरभूत माप_प्रकार
libcrux_ml_kem_vector_portable_rej_sample_b8(
  Eurydice_borrow_slice_u8 a,
  Eurydice_mut_borrow_slice_i16 out
)
{
  वापस libcrux_ml_kem_vector_portable_sampling_rej_sample(a, out);
}

#घोषणा LIBCRUX_ML_KEM_MLKEM768_VECTOR_U_COMPRESSION_FACTOR ((माप_प्रकार)10U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_C1_BLOCK_आकार (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_VECTOR_U_COMPRESSION_FACTOR / (माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_RANK ((माप_प्रकार)3U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_C1_आकार (LIBCRUX_ML_KEM_MLKEM768_C1_BLOCK_आकार * LIBCRUX_ML_KEM_MLKEM768_RANK)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_VECTOR_V_COMPRESSION_FACTOR ((माप_प्रकार)4U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_C2_आकार (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_VECTOR_V_COMPRESSION_FACTOR / (माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_आकार (LIBCRUX_ML_KEM_MLKEM768_C1_आकार + LIBCRUX_ML_KEM_MLKEM768_C2_आकार)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_आकार (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_COEFFICIENT / (माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_PUBLIC_कुंजी_आकार (LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_आकार + (माप_प्रकार)32U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_कुंजी_आकार (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_COEFFICIENT / (माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_ETA1 ((माप_प्रकार)2U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_ETA1_RANDOMNESS_आकार (LIBCRUX_ML_KEM_MLKEM768_ETA1 * (माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_ETA2 ((माप_प्रकार)2U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_ETA2_RANDOMNESS_आकार (LIBCRUX_ML_KEM_MLKEM768_ETA2 * (माप_प्रकार)64U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_IMPLICIT_REJECTION_HASH_निवेश_आकार (LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_आकार)

प्रकार Eurydice_arr_7d libcrux_ml_kem_mlkem768_Ml_Kem768_Private_कुंजी;

प्रकार Eurydice_arr_5f libcrux_ml_kem_mlkem768_Ml_Kem768_Public_कुंजी;

#घोषणा LIBCRUX_ML_KEM_MLKEM768_RANKED_BYTES_PER_RING_ELEMENT (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_BITS_PER_RING_ELEMENT / (माप_प्रकार)8U)

#घोषणा LIBCRUX_ML_KEM_MLKEM768_SECRET_कुंजी_आकार (LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_कुंजी_आकार + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_PUBLIC_कुंजी_आकार + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_आकार + LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार)

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $16size_t
*/
प्रकार काष्ठा Eurydice_arr_9e_s { Eurydice_arr_d6 तथ्य[16U]; } Eurydice_arr_9e;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_polynomial_PolynomialRingElement_1d
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_bb0_s { Eurydice_arr_9e तथ्य[3U]; } Eurydice_arr_bb0;

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल अंतरभूत Eurydice_arr_9e libcrux_ml_kem_polynomial_ZERO_d6_ea(व्योम)
{
  Eurydice_arr_9e lit;
  Eurydice_arr_d6 repeat_expression[16U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    repeat_expression[i] = libcrux_ml_kem_vector_portable_ZERO_b8();
  }
  स_नकल(lit.तथ्य, repeat_expression, (माप_प्रकार)16U * माप (Eurydice_arr_d6));
  वापस lit;
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
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_01(व्योम **_, माप_प्रकार tupled_args)
{
  वापस libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_to_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_to_uncompressed_ring_element_ea(
  Eurydice_borrow_slice_u8 serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < serialized.meta / (माप_प्रकार)24U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)24U,
            .end = i0 * (माप_प्रकार)24U + (माप_प्रकार)24U
          }
        ));
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_vector_portable_deserialize_12_b8(bytes);
    re.तथ्य[i0] = uu____0;
  }
  वापस re;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cpa_deserialize_vector_68(
  Eurydice_borrow_slice_u8 secret_कुंजी,
  Eurydice_arr_bb0 *secret_as_ntt
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_serialize_deserialize_to_uncompressed_ring_element_ea(Eurydice_slice_subslice_shared_c8(secret_कुंजी,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .start = i0 * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT,
              .end = (i0 + (माप_प्रकार)1U) * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT
            }
          )));
    secret_as_ntt->तथ्य[i0] = uu____0;
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
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_30(
  व्योम **_,
  माप_प्रकार tupled_args
)
{
  वापस libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 10
*/
अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_compress_decompress_ciphertext_coefficient_ef(Eurydice_arr_d6 a)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.तथ्य[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_public_integers_classify_27_39(LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS));
    decompressed = (int32_t)((uint32_t)decompressed << 1U) + (int32_t)((uint32_t)1 << (uint32_t)10);
    decompressed >>= (uint32_t)(10 + 1);
    a.तथ्य[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  वापस a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 10
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_decompress_ciphertext_coefficient_b8_ef(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_compress_decompress_ciphertext_coefficient_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(Eurydice_borrow_slice_u8 serialized)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < serialized.meta / (माप_प्रकार)20U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)20U,
            .end = i0 * (माप_प्रकार)20U + (माप_प्रकार)20U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_vector_portable_deserialize_10_b8(bytes);
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_vector_portable_decompress_ciphertext_coefficient_b8_ef(coefficient);
    re.तथ्य[i0] = uu____0;
  }
  वापस re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_f7(
  Eurydice_borrow_slice_u8 serialized
)
{
  वापस libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(serialized);
}

प्रकार काष्ठा libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2_s
{
  Eurydice_arr_d6 fst;
  Eurydice_arr_d6 snd;
}
libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2;

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_layer_int_vec_step
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2
libcrux_ml_kem_ntt_ntt_layer_int_vec_step_ea(
  Eurydice_arr_d6 a,
  Eurydice_arr_d6 b,
  int16_t zeta_r
)
{
  Eurydice_arr_d6
  t = libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(b, zeta_r);
  b = libcrux_ml_kem_vector_portable_sub_b8(a, &t);
  a = libcrux_ml_kem_vector_portable_add_b8(a, &t);
  वापस
    (
      KRML_CLITERAL(libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2){
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(
  माप_प्रकार *zeta_i,
  Eurydice_arr_9e *re,
  माप_प्रकार layer,
  माप_प्रकार _initial_coefficient_bound
)
{
  माप_प्रकार step = (माप_प्रकार)1U << (uint32_t)layer;
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < (माप_प्रकार)128U >> (uint32_t)layer; i0++)
  {
    माप_प्रकार round = i0;
    zeta_i[0U]++;
    माप_प्रकार offset = round * step * (माप_प्रकार)2U;
    माप_प्रकार offset_vec = offset / (माप_प्रकार)16U;
    माप_प्रकार step_vec = step / (माप_प्रकार)16U;
    क्रम (माप_प्रकार i = offset_vec; i < offset_vec + step_vec; i++)
    {
      माप_प्रकार j = i;
      libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2
      uu____0 =
        libcrux_ml_kem_ntt_ntt_layer_int_vec_step_ea(re->तथ्य[j],
          re->तथ्य[j + step_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_d6 x = uu____0.fst;
      Eurydice_arr_d6 y = uu____0.snd;
      re->तथ्य[j] = x;
      re->तथ्य[j + step_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ntt_ntt_at_layer_3_ea(
  माप_प्रकार *zeta_i,
  Eurydice_arr_9e *re,
  माप_प्रकार _initial_coefficient_bound
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    माप_प्रकार round = i;
    zeta_i[0U]++;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_vector_portable_ntt_layer_3_step_b8(re->तथ्य[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->तथ्य[round] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ntt_ntt_at_layer_2_ea(
  माप_प्रकार *zeta_i,
  Eurydice_arr_9e *re,
  माप_प्रकार _initial_coefficient_bound
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    माप_प्रकार round = i;
    zeta_i[0U]++;
    re->तथ्य[round] =
      libcrux_ml_kem_vector_portable_ntt_layer_2_step_b8(re->तथ्य[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (माप_प्रकार)1U));
    zeta_i[0U]++;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ntt_ntt_at_layer_1_ea(
  माप_प्रकार *zeta_i,
  Eurydice_arr_9e *re,
  माप_प्रकार _initial_coefficient_bound
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    माप_प्रकार round = i;
    zeta_i[0U]++;
    re->तथ्य[round] =
      libcrux_ml_kem_vector_portable_ntt_layer_1_step_b8(re->तथ्य[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (माप_प्रकार)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (माप_प्रकार)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (माप_प्रकार)3U));
    zeta_i[0U] += (माप_प्रकार)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.poly_barrett_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_polynomial_poly_barrett_reduce_ea(Eurydice_arr_9e *myself)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_vector_portable_barrett_reduce_b8(myself->तथ्य[i0]);
    myself->तथ्य[i0] = uu____0;
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
अटल KRML_MUSTINLINE व्योम
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
अटल KRML_MUSTINLINE व्योम libcrux_ml_kem_ntt_ntt_vector_u_f7(Eurydice_arr_9e *re)
{
  माप_प्रकार zeta_i = (माप_प्रकार)0U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (माप_प्रकार)7U, (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (माप_प्रकार)6U, (माप_प्रकार)2U * (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (माप_प्रकार)5U, (माप_प्रकार)3U * (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (माप_प्रकार)4U, (माप_प्रकार)4U * (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (माप_प्रकार)5U * (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (माप_प्रकार)6U * (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (माप_प्रकार)7U * (माप_प्रकार)3328U);
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
अटल KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_30(स्थिर Eurydice_arr_2b *ciphertext)
{
  Eurydice_arr_bb0 arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_struct.तथ्य[i] =
      libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_30(&lvalue,
        i);
  }
  Eurydice_arr_bb0 u_as_ntt = arr_struct;
  क्रम
  (माप_प्रकार
    i = (माप_प्रकार)0U;
    i <
      (माप_प्रकार)1088U /
        (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (माप_प्रकार)10U / (माप_प्रकार)8U);
    i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    u_bytes =
      Eurydice_array_to_subslice_shared_d44(ciphertext,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 *
              (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (माप_प्रकार)10U / (माप_प्रकार)8U),
            .end = i0 *
              (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (माप_प्रकार)10U / (माप_प्रकार)8U)
            + LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT * (माप_प्रकार)10U / (माप_प्रकार)8U
          }
        ));
    u_as_ntt.तथ्य[i0] =
      libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_f7(u_bytes);
    libcrux_ml_kem_ntt_ntt_vector_u_f7(&u_as_ntt.तथ्य[i0]);
  }
  वापस u_as_ntt;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 4
*/
अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_compress_decompress_ciphertext_coefficient_d1(Eurydice_arr_d6 a)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.तथ्य[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_public_integers_classify_27_39(LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_MODULUS));
    decompressed = (int32_t)((uint32_t)decompressed << 1U) + (int32_t)((uint32_t)1 << (uint32_t)4);
    decompressed >>= (uint32_t)(4 + 1);
    a.तथ्य[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  वापस a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 4
*/
अटल अंतरभूत Eurydice_arr_d6
libcrux_ml_kem_vector_portable_decompress_ciphertext_coefficient_b8_d1(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_compress_decompress_ciphertext_coefficient_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(Eurydice_borrow_slice_u8 serialized)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < serialized.meta / (माप_प्रकार)8U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)8U,
            .end = i0 * (माप_प्रकार)8U + (माप_प्रकार)8U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_vector_portable_deserialize_4_b8(bytes);
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_vector_portable_decompress_ciphertext_coefficient_b8_d1(coefficient);
    re.तथ्य[i0] = uu____0;
  }
  वापस re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- COMPRESSION_FACTOR= 4
*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_b6(
  Eurydice_borrow_slice_u8 serialized
)
{
  वापस libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(serialized);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल अंतरभूत Eurydice_arr_9e libcrux_ml_kem_polynomial_ZERO_ea(व्योम)
{
  Eurydice_arr_9e lit;
  Eurydice_arr_d6 repeat_expression[16U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    repeat_expression[i] = libcrux_ml_kem_vector_portable_ZERO_b8();
  }
  स_नकल(lit.तथ्य, repeat_expression, (माप_प्रकार)16U * माप (Eurydice_arr_d6));
  वापस lit;
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
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ntt_multiply_ea(
  स्थिर Eurydice_arr_9e *myself,
  स्थिर Eurydice_arr_9e *rhs
)
{
  Eurydice_arr_9e out = libcrux_ml_kem_polynomial_ZERO_ea();
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_vector_portable_ntt_multiply_b8(&myself->तथ्य[i0],
        &rhs->तथ्य[i0],
        libcrux_ml_kem_polynomial_zeta((माप_प्रकार)64U + (माप_प्रकार)4U * i0),
        libcrux_ml_kem_polynomial_zeta((माप_प्रकार)64U + (माप_प्रकार)4U * i0 + (माप_प्रकार)1U),
        libcrux_ml_kem_polynomial_zeta((माप_प्रकार)64U + (माप_प्रकार)4U * i0 + (माप_प्रकार)2U),
        libcrux_ml_kem_polynomial_zeta((माप_प्रकार)64U + (माप_प्रकार)4U * i0 + (माप_प्रकार)3U));
    out.तथ्य[i0] = uu____0;
  }
  वापस out;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ntt_multiply_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(
  स्थिर Eurydice_arr_9e *self,
  स्थिर Eurydice_arr_9e *rhs
)
{
  वापस libcrux_ml_kem_polynomial_ntt_multiply_ea(self, rhs);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_polynomial_add_to_ring_element_68(
  Eurydice_arr_9e *myself,
  स्थिर Eurydice_arr_9e *rhs
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_vector_portable_add_b8(myself->तथ्य[i0], &rhs->तथ्य[i0]);
    myself->तथ्य[i0] = uu____0;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_polynomial_add_to_ring_element_d6_68(
  Eurydice_arr_9e *self,
  स्थिर Eurydice_arr_9e *rhs
)
{
  libcrux_ml_kem_polynomial_add_to_ring_element_68(self, rhs);
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(माप_प्रकार *zeta_i, Eurydice_arr_9e *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    माप_प्रकार round = i;
    zeta_i[0U]--;
    re->तथ्य[round] =
      libcrux_ml_kem_vector_portable_inv_ntt_layer_1_step_b8(re->तथ्य[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (माप_प्रकार)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (माप_प्रकार)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (माप_प्रकार)3U));
    zeta_i[0U] -= (माप_प्रकार)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(माप_प्रकार *zeta_i, Eurydice_arr_9e *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    माप_प्रकार round = i;
    zeta_i[0U]--;
    re->तथ्य[round] =
      libcrux_ml_kem_vector_portable_inv_ntt_layer_2_step_b8(re->तथ्य[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (माप_प्रकार)1U));
    zeta_i[0U]--;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(माप_प्रकार *zeta_i, Eurydice_arr_9e *re)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    माप_प्रकार round = i;
    zeta_i[0U]--;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_vector_portable_inv_ntt_layer_3_step_b8(re->तथ्य[round],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->तथ्य[round] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.inv_ntt_layer_int_vec_step_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2
libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_step_reduce_ea(
  Eurydice_arr_d6 a,
  Eurydice_arr_d6 b,
  int16_t zeta_r
)
{
  Eurydice_arr_d6 a_minus_b = libcrux_ml_kem_vector_portable_sub_b8(b, &a);
  a =
    libcrux_ml_kem_vector_portable_barrett_reduce_b8(libcrux_ml_kem_vector_portable_add_b8(a, &b));
  b = libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(a_minus_b, zeta_r);
  वापस
    (
      KRML_CLITERAL(libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2){
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(
  माप_प्रकार *zeta_i,
  Eurydice_arr_9e *re,
  माप_प्रकार layer
)
{
  माप_प्रकार step = (माप_प्रकार)1U << (uint32_t)layer;
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < (माप_प्रकार)128U >> (uint32_t)layer; i0++)
  {
    माप_प्रकार round = i0;
    zeta_i[0U]--;
    माप_प्रकार offset = round * step * (माप_प्रकार)2U;
    माप_प्रकार offset_vec = offset / LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR;
    माप_प्रकार step_vec = step / LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR;
    क्रम (माप_प्रकार i = offset_vec; i < offset_vec + step_vec; i++)
    {
      माप_प्रकार j = i;
      libcrux_ml_kem_vector_portable_vector_type_PortableVector_x2
      uu____0 =
        libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_step_reduce_ea(re->तथ्य[j],
          re->तथ्य[j + step_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_d6 x = uu____0.fst;
      Eurydice_arr_d6 y = uu____0.snd;
      re->तथ्य[j] = x;
      re->तथ्य[j + step_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_montgomery
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(Eurydice_arr_9e *re)
{
  माप_प्रकार zeta_i = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT / (माप_प्रकार)2U;
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (माप_प्रकार)4U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (माप_प्रकार)5U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (माप_प्रकार)6U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (माप_प्रकार)7U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_subtract_reduce_ea(स्थिर Eurydice_arr_9e *myself, Eurydice_arr_9e b)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    coefficient_normal_form =
      libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(b.तथ्य[i0],
        1441);
    Eurydice_arr_d6
    diff = libcrux_ml_kem_vector_portable_sub_b8(myself->तथ्य[i0], &coefficient_normal_form);
    Eurydice_arr_d6 red = libcrux_ml_kem_vector_portable_barrett_reduce_b8(diff);
    b.तथ्य[i0] = red;
  }
  वापस b;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_subtract_reduce_d6_ea(स्थिर Eurydice_arr_9e *self, Eurydice_arr_9e b)
{
  वापस libcrux_ml_kem_polynomial_subtract_reduce_ea(self, b);
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
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_matrix_compute_message_68(
  स्थिर Eurydice_arr_9e *v,
  स्थिर Eurydice_arr_bb0 *secret_as_ntt,
  स्थिर Eurydice_arr_bb0 *u_as_ntt
)
{
  Eurydice_arr_9e परिणाम = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_9e
    product =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&secret_as_ntt->तथ्य[i0],
        &u_as_ntt->तथ्य[i0]);
    libcrux_ml_kem_polynomial_add_to_ring_element_d6_68(&परिणाम, &product);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&परिणाम);
  वापस libcrux_ml_kem_polynomial_subtract_reduce_d6_ea(v, परिणाम);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.to_unsigned_field_modulus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_to_unsigned_representative_b8(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_serialize_compress_then_serialize_message_ea(Eurydice_arr_9e re)
{
  Eurydice_arr_ec serialized = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    coefficient = libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(re.तथ्य[i0]);
    Eurydice_arr_d6
    coefficient_compressed = libcrux_ml_kem_vector_portable_compress_1_b8(coefficient);
    Eurydice_array_u8x2
    bytes = libcrux_ml_kem_vector_portable_serialize_1_b8(coefficient_compressed);
    Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d46(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = (माप_प्रकार)2U * i0,
            .end = (माप_प्रकार)2U * i0 + (माप_प्रकार)2U
          }
        )),
      Eurydice_array_to_slice_shared_82(&bytes),
      uint8_t);
  }
  वापस serialized;
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
अटल KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(
  स्थिर Eurydice_arr_bb0 *secret_कुंजी,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_bb0
  u_as_ntt = libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_30(ciphertext);
  Eurydice_arr_9e
  v =
    libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_b6(Eurydice_array_to_subslice_from_shared_5f0(ciphertext,
        (माप_प्रकार)960U));
  Eurydice_arr_9e message = libcrux_ml_kem_matrix_compute_message_68(&v, secret_कुंजी, &u_as_ntt);
  वापस libcrux_ml_kem_serialize_compress_then_serialize_message_ea(message);
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
अटल KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cpa_decrypt_01(
  Eurydice_borrow_slice_u8 secret_कुंजी,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_bb0 arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_struct.तथ्य[i] = libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_01(&lvalue, i);
  }
  Eurydice_arr_bb0 secret_कुंजी_unpacked = arr_struct;
  libcrux_ml_kem_ind_cpa_deserialize_vector_68(secret_कुंजी, &secret_कुंजी_unpacked);
  वापस libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(&secret_कुंजी_unpacked, ciphertext);
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.G_4a
with const generics
- K= 3
*/
अटल अंतरभूत Eurydice_arr_c7
libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_borrow_slice_u8 निवेश)
{
  वापस libcrux_ml_kem_hash_functions_portable_G(निवेश);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 32
*/
अटल अंतरभूत Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_PRF_ce(Eurydice_borrow_slice_u8 निवेश)
{
  Eurydice_arr_ec digest = { .तथ्य = { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_01(&digest), निवेश);
  वापस digest;
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
अटल अंतरभूत Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_borrow_slice_u8 निवेश)
{
  वापस libcrux_ml_kem_hash_functions_portable_PRF_ce(निवेश);
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_bb0
with const generics
- $3size_t
*/
प्रकार काष्ठा Eurydice_arr_c10_s { Eurydice_arr_bb0 तथ्य[3U]; } Eurydice_arr_c10;

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.IndCpaPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
प्रकार काष्ठा libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51_s
{
  Eurydice_arr_bb0 t_as_ntt;
  Eurydice_arr_ec seed_for_A;
  Eurydice_arr_c10 A;
}
libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51;

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.default_8b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
अटल अंतरभूत libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51
libcrux_ml_kem_ind_cpa_unpacked_default_8b_68(व्योम)
{
  Eurydice_arr_bb0 uu____0;
  Eurydice_arr_9e repeat_expression0[3U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    repeat_expression0[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  स_नकल(uu____0.तथ्य, repeat_expression0, (माप_प्रकार)3U * माप (Eurydice_arr_9e));
  Eurydice_arr_ec uu____1 = { .तथ्य = { 0U } };
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51 lit0;
  lit0.t_as_ntt = uu____0;
  lit0.seed_for_A = uu____1;
  Eurydice_arr_bb0 repeat_expression1[3U];
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < (माप_प्रकार)3U; i0++)
  {
    Eurydice_arr_bb0 lit;
    Eurydice_arr_9e repeat_expression[3U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
    {
      repeat_expression[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    }
    स_नकल(lit.तथ्य, repeat_expression, (माप_प्रकार)3U * माप (Eurydice_arr_9e));
    repeat_expression1[i0] = lit;
  }
  स_नकल(lit0.A.तथ्य, repeat_expression1, (माप_प्रकार)3U * माप (Eurydice_arr_bb0));
  वापस lit0;
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
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_to_reduced_ring_element_ea(
  Eurydice_borrow_slice_u8 serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < serialized.meta / (माप_प्रकार)24U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    bytes =
      Eurydice_slice_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * (माप_प्रकार)24U,
            .end = i0 * (माप_प्रकार)24U + (माप_प्रकार)24U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_vector_portable_deserialize_12_b8(bytes);
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_vector_portable_cond_subtract_3329_b8(coefficient);
    re.तथ्य[i0] = uu____0;
  }
  वापस re;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(
  Eurydice_borrow_slice_u8 public_कुंजी,
  Eurydice_arr_bb0 *deserialized_pk
)
{
  क्रम
  (माप_प्रकार
    i = (माप_प्रकार)0U;
    i < public_कुंजी.meta / LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT;
    i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_borrow_slice_u8
    ring_element =
      Eurydice_slice_subslice_shared_c8(public_कुंजी,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT,
            .end = i0 * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT +
              LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT
          }
        ));
    Eurydice_arr_9e
    uu____0 = libcrux_ml_kem_serialize_deserialize_to_reduced_ring_element_ea(ring_element);
    deserialized_pk->तथ्य[i0] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final
with const generics
- K= 3
*/
अटल अंतरभूत Eurydice_arr_1b0
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_78(
  स्थिर Eurydice_arr_810 *निवेश
)
{
  Eurydice_arr_1b0 shake128_state;
  Eurydice_arr_7c repeat_expression[3U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    repeat_expression[i] = libcrux_sha3_portable_incremental_shake128_init();
  }
  स_नकल(shake128_state.तथ्य, repeat_expression, (माप_प्रकार)3U * माप (Eurydice_arr_7c));
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_sha3_portable_incremental_shake128_absorb_final(&shake128_state.तथ्य[i0],
      Eurydice_array_to_slice_shared_e9(&निवेश->तथ्य[i0]));
  }
  वापस shake128_state;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final_4a
with const generics
- K= 3
*/
अटल अंतरभूत Eurydice_arr_1b0
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_78(
  स्थिर Eurydice_arr_810 *निवेश
)
{
  वापस libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_78(निवेश);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks
with const generics
- K= 3
*/
अटल अंतरभूत Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_first_three_blocks_78(
  Eurydice_arr_1b0 *st
)
{
  Eurydice_arr_7e
  out = { .तथ्य = { { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } } } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_first_three_blocks(&st->तथ्य[i0],
      Eurydice_array_to_slice_mut_48(&out.तथ्य[i0]));
  }
  वापस out;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks_4a
with const generics
- K= 3
*/
अटल अंतरभूत Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_first_three_blocks_4a_78(
  Eurydice_arr_1b0 *self
)
{
  वापस libcrux_ml_kem_hash_functions_portable_shake128_squeeze_first_three_blocks_78(self);
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
अटल KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_uniform_distribution_अग्र_b6(
  स्थिर Eurydice_arr_7e *randomness,
  Eurydice_arr_eb *sampled_coefficients,
  Eurydice_arr_b1 *out
)
{
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < (माप_प्रकार)3U; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)504U / (माप_प्रकार)24U; i++)
    {
      माप_प्रकार r = i;
      अगर (sampled_coefficients->तथ्य[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        माप_प्रकार
        sampled =
          libcrux_ml_kem_vector_portable_rej_sample_b8(Eurydice_array_to_subslice_shared_d45(&randomness->तथ्य[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .start = r * (माप_प्रकार)24U,
                  .end = r * (माप_प्रकार)24U + (माप_प्रकार)24U
                }
              )),
            Eurydice_array_to_subslice_mut_e7(&out->तथ्य[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .start = sampled_coefficients->तथ्य[i1],
                  .end = sampled_coefficients->तथ्य[i1] + (माप_प्रकार)16U
                }
              )));
        माप_प्रकार uu____0 = i1;
        sampled_coefficients->तथ्य[uu____0] += sampled;
      }
    }
  }
  bool done = true;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    अगर (sampled_coefficients->तथ्य[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
    {
      sampled_coefficients->तथ्य[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT;
    }
    अन्यथा
    {
      done = false;
    }
  }
  वापस done;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block
with const generics
- K= 3
*/
अटल अंतरभूत Eurydice_arr_2c
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_अग्र_block_78(Eurydice_arr_1b0 *st)
{
  Eurydice_arr_2c
  out = { .तथ्य = { { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } } } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_अग्र_block(&st->तथ्य[i0],
      Eurydice_array_to_slice_mut_2c(&out.तथ्य[i0]));
  }
  वापस out;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block_4a
with const generics
- K= 3
*/
अटल अंतरभूत Eurydice_arr_2c
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_अग्र_block_4a_78(
  Eurydice_arr_1b0 *self
)
{
  वापस libcrux_ml_kem_hash_functions_portable_shake128_squeeze_अग्र_block_78(self);
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
अटल KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_uniform_distribution_अग्र_b60(
  स्थिर Eurydice_arr_2c *randomness,
  Eurydice_arr_eb *sampled_coefficients,
  Eurydice_arr_b1 *out
)
{
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < (माप_प्रकार)3U; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)168U / (माप_प्रकार)24U; i++)
    {
      माप_प्रकार r = i;
      अगर (sampled_coefficients->तथ्य[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
      {
        माप_प्रकार
        sampled =
          libcrux_ml_kem_vector_portable_rej_sample_b8(Eurydice_array_to_subslice_shared_d46(&randomness->तथ्य[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .start = r * (माप_प्रकार)24U,
                  .end = r * (माप_प्रकार)24U + (माप_प्रकार)24U
                }
              )),
            Eurydice_array_to_subslice_mut_e7(&out->तथ्य[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .start = sampled_coefficients->तथ्य[i1],
                  .end = sampled_coefficients->तथ्य[i1] + (माप_प्रकार)16U
                }
              )));
        माप_प्रकार uu____0 = i1;
        sampled_coefficients->तथ्य[uu____0] += sampled;
      }
    }
  }
  bool done = true;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    अगर (sampled_coefficients->तथ्य[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT)
    {
      sampled_coefficients->तथ्य[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_IN_RING_ELEMENT;
    }
    अन्यथा
    {
      done = false;
    }
  }
  वापस done;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_from_i16_array_ea(Eurydice_borrow_slice_i16 a)
{
  Eurydice_arr_9e परिणाम = libcrux_ml_kem_polynomial_ZERO_ea();
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_vector_portable_from_i16_array_b8(Eurydice_slice_subslice_shared_a6(a,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .start = i0 * (माप_प्रकार)16U,
              .end = (i0 + (माप_प्रकार)1U) * (माप_प्रकार)16U
            }
          )));
    परिणाम.तथ्य[i0] = uu____0;
  }
  वापस परिणाम;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_borrow_slice_i16 a)
{
  वापस libcrux_ml_kem_polynomial_from_i16_array_ea(a);
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
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_xof_call_mut_0a_91(व्योम **_, Eurydice_arr_5b tupled_args)
{
  Eurydice_arr_5b s = tupled_args;
  वापस
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_to_subslice_shared_e70(&s,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)256U })));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_xof
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
अटल KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_sampling_sample_from_xof_91(स्थिर Eurydice_arr_810 *seeds)
{
  Eurydice_arr_eb sampled_coefficients = { .तथ्य = { 0U } };
  Eurydice_arr_b1
  out = { .तथ्य = { { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } } } };
  Eurydice_arr_1b0
  xof_state = libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_78(seeds);
  Eurydice_arr_7e
  randomness0 =
    libcrux_ml_kem_hash_functions_portable_shake128_squeeze_first_three_blocks_4a_78(&xof_state);
  bool
  done =
    libcrux_ml_kem_sampling_sample_from_uniform_distribution_अग्र_b6(&randomness0,
      &sampled_coefficients,
      &out);
  जबतक (true)
  {
    अगर (done)
    {
      अवरोध;
    }
    अन्यथा
    {
      Eurydice_arr_2c
      randomness =
        libcrux_ml_kem_hash_functions_portable_shake128_squeeze_अग्र_block_4a_78(&xof_state);
      done =
        libcrux_ml_kem_sampling_sample_from_uniform_distribution_अग्र_b60(&randomness,
          &sampled_coefficients,
          &out);
    }
  }
  Eurydice_arr_bb0 arr_mapped_str;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_mapped_str.तथ्य[i] =
      libcrux_ml_kem_sampling_sample_from_xof_call_mut_0a_91(&lvalue,
        out.तथ्य[i]);
  }
  वापस arr_mapped_str;
}

/**
A monomorphic instance of libcrux_ml_kem.matrix.sample_matrix_A
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_matrix_sample_matrix_A_91(
  Eurydice_arr_c10 *A_transpose,
  स्थिर Eurydice_arr_31 *seed,
  bool transpose
)
{
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < (माप_प्रकार)3U; i0++)
  {
    माप_प्रकार i1 = i0;
    Eurydice_arr_810 seeds;
    Eurydice_arr_31 repeat_expression[3U];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
    {
      repeat_expression[i] =
        core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)34U,
          seed,
          uint8_t,
          Eurydice_arr_31);
    }
    स_नकल(seeds.तथ्य, repeat_expression, (माप_प्रकार)3U * माप (Eurydice_arr_31));
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
    {
      माप_प्रकार j = i;
      seeds.तथ्य[j].तथ्य[32U] = (uint8_t)i1;
      seeds.तथ्य[j].तथ्य[33U] = (uint8_t)j;
    }
    Eurydice_arr_bb0 sampled = libcrux_ml_kem_sampling_sample_from_xof_91(&seeds);
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
    {
      माप_प्रकार j = i;
      Eurydice_arr_9e sample = sampled.तथ्य[j];
      अगर (transpose)
      {
        A_transpose->तथ्य[j].तथ्य[i1] = sample;
      }
      अन्यथा
      {
        A_transpose->तथ्य[i1].तथ्य[j] = sample;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cpa_build_unpacked_public_कुंजी_mut_05(
  Eurydice_borrow_slice_u8 public_कुंजी,
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51 *unpacked_public_कुंजी
)
{
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(Eurydice_slice_subslice_to_shared_72(public_कुंजी,
      (माप_प्रकार)1152U),
    &unpacked_public_कुंजी->t_as_ntt);
  Eurydice_borrow_slice_u8
  seed = Eurydice_slice_subslice_from_shared_6d(public_कुंजी, (माप_प्रकार)1152U);
  Eurydice_arr_c10 *uu____0 = &unpacked_public_कुंजी->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31 lvalue = libcrux_ml_kem_utils_into_padded_array_de(seed);
  libcrux_ml_kem_matrix_sample_matrix_A_91(uu____0, &lvalue, false);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.build_unpacked_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
*/
अटल KRML_MUSTINLINE libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51
libcrux_ml_kem_ind_cpa_build_unpacked_public_कुंजी_05(Eurydice_borrow_slice_u8 public_कुंजी)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51
  unpacked_public_कुंजी = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68();
  libcrux_ml_kem_ind_cpa_build_unpacked_public_कुंजी_mut_05(public_कुंजी, &unpacked_public_कुंजी);
  वापस unpacked_public_कुंजी;
}

/**
A monomorphic instance of n-tuple
with types Eurydice_arr_bb0, libcrux_ml_kem_polynomial_PolynomialRingElement_1d

*/
प्रकार काष्ठा tuple_c6_s
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
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_87(व्योम **_, माप_प्रकार tupled_args)
{
  वापस libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRFxN
with const generics
- K= 3
- LEN= 128
*/
अटल अंतरभूत Eurydice_arr_58
libcrux_ml_kem_hash_functions_portable_PRFxN_3b(स्थिर Eurydice_arr_fd *निवेश)
{
  Eurydice_arr_58
  out = { .तथ्य = { { .तथ्य = { 0U } }, { .तथ्य = { 0U } }, { .तथ्य = { 0U } } } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_78(&out.तथ्य[i0]),
      Eurydice_array_to_slice_shared_b5(&निवेश->तथ्य[i0]));
  }
  वापस out;
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
अटल अंतरभूत Eurydice_arr_58
libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(स्थिर Eurydice_arr_fd *निवेश)
{
  वापस libcrux_ml_kem_hash_functions_portable_PRFxN_3b(निवेश);
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
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_binomial_distribution_2_ea(
  Eurydice_borrow_slice_u8 randomness
)
{
  Eurydice_arr_04 sampled_i16s = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < randomness.meta / (माप_प्रकार)4U; i0++)
  {
    माप_प्रकार chunk_संख्या = i0;
    Eurydice_borrow_slice_u8
    byte_chunk =
      Eurydice_slice_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = chunk_संख्या * (माप_प्रकार)4U,
            .end = chunk_संख्या * (माप_प्रकार)4U + (माप_प्रकार)4U
          }
        ));
    uint32_t
    random_bits_as_u32 =
      (((uint32_t)byte_chunk.ptr[0U] | (uint32_t)byte_chunk.ptr[1U] << 8U) |
        (uint32_t)byte_chunk.ptr[2U] << 16U)
      | (uint32_t)byte_chunk.ptr[3U] << 24U;
    uint32_t even_bits = random_bits_as_u32 & 1431655765U;
    uint32_t odd_bits = random_bits_as_u32 >> 1U & 1431655765U;
    uint32_t coin_toss_outcomes = even_bits + odd_bits;
    क्रम (uint32_t i = 0U; i < 32U / 4U; i++)
    {
      uint32_t outcome_set = i;
      uint32_t outcome_set0 = outcome_set * 4U;
      int16_t outcome_1 = (int16_t)(coin_toss_outcomes >> (uint32_t)outcome_set0 & 3U);
      int16_t outcome_2 = (int16_t)(coin_toss_outcomes >> (uint32_t)(outcome_set0 + 2U) & 3U);
      माप_प्रकार offset = (माप_प्रकार)(outcome_set0 >> 2U);
      sampled_i16s.तथ्य[(माप_प्रकार)8U * chunk_संख्या + offset] = outcome_1 - outcome_2;
    }
  }
  वापस
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_to_slice_shared_99(&sampled_i16s));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_binomial_distribution
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- ETA= 2
*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_binomial_distribution_66(
  Eurydice_borrow_slice_u8 randomness
)
{
  वापस libcrux_ml_kem_sampling_sample_from_binomial_distribution_2_ea(randomness);
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_7
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम libcrux_ml_kem_ntt_ntt_at_layer_7_ea(Eurydice_arr_9e *re)
{
  माप_प्रकार step = LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT / (माप_प्रकार)2U;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < step; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_d6
    t = libcrux_ml_kem_vector_portable_multiply_by_constant_b8(re->तथ्य[j + step], -1600);
    re->तथ्य[j + step] = libcrux_ml_kem_vector_portable_sub_b8(re->तथ्य[j], &t);
    Eurydice_arr_d6 uu____1 = libcrux_ml_kem_vector_portable_add_b8(re->तथ्य[j], &t);
    re->तथ्य[j] = uu____1;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_binomially_sampled_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(Eurydice_arr_9e *re)
{
  libcrux_ml_kem_ntt_ntt_at_layer_7_ea(re);
  माप_प्रकार zeta_i = (माप_प्रकार)1U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (माप_प्रकार)6U, (माप_प्रकार)11207U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (माप_प्रकार)5U,
    (माप_प्रकार)11207U + (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (माप_प्रकार)4U,
    (माप_प्रकार)11207U + (माप_प्रकार)2U * (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (माप_प्रकार)11207U + (माप_प्रकार)3U * (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (माप_प्रकार)11207U + (माप_प्रकार)4U * (माप_प्रकार)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (माप_प्रकार)11207U + (माप_प्रकार)5U * (माप_प्रकार)3328U);
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
अटल KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_bf(
  Eurydice_arr_bb0 *re_as_ntt,
  स्थिर Eurydice_arr_fa0 *prf_निवेश,
  uint8_t domain_separator
)
{
  Eurydice_arr_fd prf_inputs;
  Eurydice_arr_fa0 repeat_expression[3U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    repeat_expression[i] =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)33U,
        prf_निवेश,
        uint8_t,
        Eurydice_arr_fa0);
  }
  स_नकल(prf_inputs.तथ्य, repeat_expression, (माप_प्रकार)3U * माप (Eurydice_arr_fa0));
  domain_separator = libcrux_ml_kem_utils_prf_निवेश_inc_78(&prf_inputs, domain_separator);
  Eurydice_arr_58 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(&prf_inputs);
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_binomial_distribution_66(Eurydice_array_to_slice_shared_78(&prf_outputs.तथ्य[i0]));
    re_as_ntt->तथ्य[i0] = uu____0;
    libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(&re_as_ntt->तथ्य[i0]);
  }
  वापस domain_separator;
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
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_87(व्योम **_, माप_प्रकार tupled_args)
{
  वापस libcrux_ml_kem_polynomial_ZERO_d6_ea();
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
अटल KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_bf(
  स्थिर Eurydice_arr_fa0 *prf_निवेश,
  uint8_t domain_separator,
  Eurydice_arr_bb0 *error_1
)
{
  Eurydice_arr_fd prf_inputs;
  Eurydice_arr_fa0 repeat_expression[3U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    repeat_expression[i] =
      core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)33U,
        prf_निवेश,
        uint8_t,
        Eurydice_arr_fa0);
  }
  स_नकल(prf_inputs.तथ्य, repeat_expression, (माप_प्रकार)3U * माप (Eurydice_arr_fa0));
  domain_separator = libcrux_ml_kem_utils_prf_निवेश_inc_78(&prf_inputs, domain_separator);
  Eurydice_arr_58 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(&prf_inputs);
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_binomial_distribution_66(Eurydice_array_to_slice_shared_78(&prf_outputs.तथ्य[i0]));
    error_1->तथ्य[i0] = uu____0;
  }
  वापस domain_separator;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 128
*/
अटल अंतरभूत Eurydice_arr_89
libcrux_ml_kem_hash_functions_portable_PRF_ec(Eurydice_borrow_slice_u8 निवेश)
{
  Eurydice_arr_89 digest = { .तथ्य = { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_to_slice_mut_78(&digest), निवेश);
  वापस digest;
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
अटल अंतरभूत Eurydice_arr_89
libcrux_ml_kem_hash_functions_portable_PRF_4a_3b0(Eurydice_borrow_slice_u8 निवेश)
{
  वापस libcrux_ml_kem_hash_functions_portable_PRF_ec(निवेश);
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
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_matrix_compute_vector_u_call_mut_a8_68(व्योम **_, माप_प्रकार tupled_args)
{
  वापस libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_polynomial_add_error_reduce_ea(
  Eurydice_arr_9e *myself,
  स्थिर Eurydice_arr_9e *error
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_d6
    coefficient_normal_form =
      libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(myself->तथ्य[j],
        1441);
    Eurydice_arr_d6
    योग = libcrux_ml_kem_vector_portable_add_b8(coefficient_normal_form, &error->तथ्य[j]);
    Eurydice_arr_d6 red = libcrux_ml_kem_vector_portable_barrett_reduce_b8(योग);
    myself->तथ्य[j] = red;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_polynomial_add_error_reduce_d6_ea(
  Eurydice_arr_9e *self,
  स्थिर Eurydice_arr_9e *error
)
{
  libcrux_ml_kem_polynomial_add_error_reduce_ea(self, error);
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
अटल KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_matrix_compute_vector_u_68(
  स्थिर Eurydice_arr_c10 *a_as_ntt,
  स्थिर Eurydice_arr_bb0 *r_as_ntt,
  स्थिर Eurydice_arr_bb0 *error_1
)
{
  Eurydice_arr_bb0 arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_struct.तथ्य[i] = libcrux_ml_kem_matrix_compute_vector_u_call_mut_a8_68(&lvalue, i);
  }
  Eurydice_arr_bb0 परिणाम = arr_struct;
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < (माप_प्रकार)3U; i0++)
  {
    माप_प्रकार i1 = i0;
    स्थिर Eurydice_arr_bb0 *row = &a_as_ntt->तथ्य[i1];
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
    {
      माप_प्रकार j = i;
      स्थिर Eurydice_arr_9e *a_element = &row->तथ्य[j];
      Eurydice_arr_9e
      product = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(a_element, &r_as_ntt->तथ्य[j]);
      libcrux_ml_kem_polynomial_add_to_ring_element_d6_68(&परिणाम.तथ्य[i1], &product);
    }
    libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&परिणाम.तथ्य[i1]);
    libcrux_ml_kem_polynomial_add_error_reduce_d6_ea(&परिणाम.तथ्य[i1], &error_1->तथ्य[i1]);
  }
  वापस परिणाम;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 10
*/
अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_compress_compress_ef(Eurydice_arr_d6 a)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_vector_portable_compress_compress_ciphertext_coefficient((uint8_t)10,
          libcrux_secrets_int_as_u16_f5(a.तथ्य[i0])));
    a.तथ्य[i0] = uu____0;
  }
  वापस a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 10
*/
अटल अंतरभूत Eurydice_arr_d6 libcrux_ml_kem_vector_portable_compress_b8_ef(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_compress_compress_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- OUT_LEN= 320
*/
अटल KRML_MUSTINLINE Eurydice_arr_b0
libcrux_ml_kem_serialize_compress_then_serialize_10_e1(स्थिर Eurydice_arr_9e *re)
{
  Eurydice_arr_b0 serialized = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    coefficient =
      libcrux_ml_kem_vector_portable_compress_b8_ef(libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(re->तथ्य[i0]));
    Eurydice_arr_fc bytes = libcrux_ml_kem_vector_portable_serialize_10_b8(coefficient);
    Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d413(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = (माप_प्रकार)20U * i0,
            .end = (माप_प्रकार)20U * i0 + (माप_प्रकार)20U
          }
        )),
      Eurydice_array_to_slice_shared_8f(&bytes),
      uint8_t);
  }
  वापस serialized;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
- OUT_LEN= 320
*/
अटल KRML_MUSTINLINE Eurydice_arr_b0
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_f7(स्थिर Eurydice_arr_9e *re)
{
  वापस libcrux_ml_kem_serialize_compress_then_serialize_10_e1(re);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cpa_compress_then_serialize_u_21(
  Eurydice_arr_bb0 निवेश,
  Eurydice_mut_borrow_slice_u8 out
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_9e re = निवेश.तथ्य[i0];
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_c8(out,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * ((माप_प्रकार)960U / (माप_प्रकार)3U),
            .end = (i0 + (माप_प्रकार)1U) * ((माप_प्रकार)960U / (माप_प्रकार)3U)
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_b0
    lvalue = libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_f7(&re);
    Eurydice_slice_copy(uu____0, Eurydice_array_to_slice_shared_56(&lvalue), uint8_t);
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
अटल KRML_MUSTINLINE tuple_c6
libcrux_ml_kem_ind_cpa_encrypt_c1_87(
  Eurydice_borrow_slice_u8 randomness,
  स्थिर Eurydice_arr_c10 *matrix,
  Eurydice_mut_borrow_slice_u8 ciphertext
)
{
  Eurydice_arr_fa0 prf_निवेश = libcrux_ml_kem_utils_into_padded_array_29(randomness);
  Eurydice_arr_bb0 arr_struct0;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_struct0.तथ्य[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_87(&lvalue, i);
  }
  Eurydice_arr_bb0 r_as_ntt = arr_struct0;
  uint8_t
  domain_separator0 =
    libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_bf(&r_as_ntt,
      &prf_निवेश,
      0U);
  Eurydice_arr_bb0 arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_struct.तथ्य[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_87(&lvalue, i);
  }
  Eurydice_arr_bb0 error_1 = arr_struct;
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_bf(&prf_निवेश,
      domain_separator0,
      &error_1);
  prf_निवेश.तथ्य[32U] = domain_separator;
  Eurydice_arr_89
  prf_output =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b0(Eurydice_array_to_slice_shared_b5(&prf_निवेश));
  Eurydice_arr_9e
  error_2 =
    libcrux_ml_kem_sampling_sample_from_binomial_distribution_66(Eurydice_array_to_slice_shared_78(&prf_output));
  Eurydice_arr_bb0 u = libcrux_ml_kem_matrix_compute_vector_u_68(matrix, &r_as_ntt, &error_1);
  libcrux_ml_kem_ind_cpa_compress_then_serialize_u_21(u, ciphertext);
  वापस (KRML_CLITERAL(tuple_c6){ .fst = r_as_ntt, .snd = error_2 });
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_message_ea(
  स्थिर Eurydice_arr_ec *serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)16U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    coefficient_compressed =
      libcrux_ml_kem_vector_portable_deserialize_1_b8(Eurydice_array_to_subslice_shared_d4(serialized,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .start = (माप_प्रकार)2U * i0,
              .end = (माप_प्रकार)2U * i0 + (माप_प्रकार)2U
            }
          )));
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_vector_portable_decompress_1_b8(coefficient_compressed);
    re.तथ्य[i0] = uu____0;
  }
  वापस re;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_add_message_error_reduce_ea(
  स्थिर Eurydice_arr_9e *myself,
  स्थिर Eurydice_arr_9e *message,
  Eurydice_arr_9e परिणाम
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    coefficient_normal_form =
      libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(परिणाम.तथ्य[i0],
        1441);
    Eurydice_arr_d6
    sum1 = libcrux_ml_kem_vector_portable_add_b8(myself->तथ्य[i0], &message->तथ्य[i0]);
    Eurydice_arr_d6 sum2 = libcrux_ml_kem_vector_portable_add_b8(coefficient_normal_form, &sum1);
    Eurydice_arr_d6 red = libcrux_ml_kem_vector_portable_barrett_reduce_b8(sum2);
    परिणाम.तथ्य[i0] = red;
  }
  वापस परिणाम;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_add_message_error_reduce_d6_ea(
  स्थिर Eurydice_arr_9e *self,
  स्थिर Eurydice_arr_9e *message,
  Eurydice_arr_9e परिणाम
)
{
  वापस libcrux_ml_kem_polynomial_add_message_error_reduce_ea(self, message, परिणाम);
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
अटल KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_matrix_compute_ring_element_v_68(
  स्थिर Eurydice_arr_bb0 *t_as_ntt,
  स्थिर Eurydice_arr_bb0 *r_as_ntt,
  स्थिर Eurydice_arr_9e *error_2,
  स्थिर Eurydice_arr_9e *message
)
{
  Eurydice_arr_9e परिणाम = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_9e
    product =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&t_as_ntt->तथ्य[i0],
        &r_as_ntt->तथ्य[i0]);
    libcrux_ml_kem_polynomial_add_to_ring_element_d6_68(&परिणाम, &product);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&परिणाम);
  वापस libcrux_ml_kem_polynomial_add_message_error_reduce_d6_ea(error_2, message, परिणाम);
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 4
*/
अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_vector_portable_compress_compress_d1(Eurydice_arr_d6 a)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_VECTOR_TRAITS_FIELD_ELEMENTS_IN_VECTOR; i++)
  {
    माप_प्रकार i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_vector_portable_compress_compress_ciphertext_coefficient((uint8_t)4,
          libcrux_secrets_int_as_u16_f5(a.तथ्य[i0])));
    a.तथ्य[i0] = uu____0;
  }
  वापस a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 4
*/
अटल अंतरभूत Eurydice_arr_d6 libcrux_ml_kem_vector_portable_compress_b8_d1(Eurydice_arr_d6 a)
{
  वापस libcrux_ml_kem_vector_portable_compress_compress_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_serialize_compress_then_serialize_4_ea(
  Eurydice_arr_9e re,
  Eurydice_mut_borrow_slice_u8 serialized
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    coefficient =
      libcrux_ml_kem_vector_portable_compress_b8_d1(libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(re.तथ्य[i0]));
    Eurydice_array_u8x8 bytes = libcrux_ml_kem_vector_portable_serialize_4_b8(coefficient);
    Eurydice_slice_copy(Eurydice_slice_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = (माप_प्रकार)8U * i0,
            .end = (माप_प्रकार)8U * i0 + (माप_प्रकार)8U
          }
        )),
      Eurydice_array_to_slice_shared_6e(&bytes),
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_v_30(
  Eurydice_arr_9e re,
  Eurydice_mut_borrow_slice_u8 out
)
{
  libcrux_ml_kem_serialize_compress_then_serialize_4_ea(re, out);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- V_COMPRESSION_FACTOR= 4
- C2_LEN= 128
*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cpa_encrypt_c2_30(
  स्थिर Eurydice_arr_bb0 *t_as_ntt,
  स्थिर Eurydice_arr_bb0 *r_as_ntt,
  स्थिर Eurydice_arr_9e *error_2,
  स्थिर Eurydice_arr_ec *message,
  Eurydice_mut_borrow_slice_u8 ciphertext
)
{
  Eurydice_arr_9e
  message_as_ring_element =
    libcrux_ml_kem_serialize_deserialize_then_decompress_message_ea(message);
  Eurydice_arr_9e
  v =
    libcrux_ml_kem_matrix_compute_ring_element_v_68(t_as_ntt,
      r_as_ntt,
      error_2,
      &message_as_ring_element);
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
अटल KRML_MUSTINLINE Eurydice_arr_2b
libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(
  स्थिर libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51 *public_कुंजी,
  स्थिर Eurydice_arr_ec *message,
  Eurydice_borrow_slice_u8 randomness
)
{
  Eurydice_arr_2b ciphertext = { .तथ्य = { 0U } };
  tuple_c6
  uu____0 =
    libcrux_ml_kem_ind_cpa_encrypt_c1_87(randomness,
      &public_कुंजी->A,
      Eurydice_array_to_subslice_mut_d414(&ciphertext,
        (KRML_CLITERAL(core_ops_range_Range_87){ .start = (माप_प्रकार)0U, .end = (माप_प्रकार)960U })));
  Eurydice_arr_bb0 r_as_ntt = uu____0.fst;
  Eurydice_arr_9e error_2 = uu____0.snd;
  libcrux_ml_kem_ind_cpa_encrypt_c2_30(&public_कुंजी->t_as_ntt,
    &r_as_ntt,
    &error_2,
    message,
    Eurydice_array_to_subslice_from_mut_5f3(&ciphertext, (माप_प्रकार)960U));
  वापस ciphertext;
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
अटल KRML_MUSTINLINE Eurydice_arr_2b
libcrux_ml_kem_ind_cpa_encrypt_d5(
  Eurydice_borrow_slice_u8 public_कुंजी,
  स्थिर Eurydice_arr_ec *message,
  Eurydice_borrow_slice_u8 randomness
)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51
  unpacked_public_कुंजी = libcrux_ml_kem_ind_cpa_build_unpacked_public_कुंजी_05(public_कुंजी);
  वापस libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&unpacked_public_कुंजी, message, randomness);
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
अटल KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_variant_kdf_39_52(
  Eurydice_borrow_slice_u8 shared_secret,
  स्थिर Eurydice_arr_2b *_
)
{
  Eurydice_arr_ec out = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_01(&out), shared_secret, uint8_t);
  वापस out;
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
अटल KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_decapsulate_fd(
  स्थिर Eurydice_arr_7d *private_कुंजी,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  Eurydice_borrow_slice_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_private_कुंजी_64(Eurydice_array_to_slice_shared_51(private_कुंजी));
  Eurydice_borrow_slice_u8 ind_cpa_secret_कुंजी = uu____0.fst;
  Eurydice_borrow_slice_u8 ind_cpa_public_कुंजी = uu____0.snd;
  Eurydice_borrow_slice_u8 ind_cpa_public_कुंजी_hash = uu____0.thd;
  Eurydice_borrow_slice_u8 implicit_rejection_मूल्य = uu____0.f3;
  Eurydice_arr_ec decrypted = libcrux_ml_kem_ind_cpa_decrypt_01(ind_cpa_secret_कुंजी, ciphertext);
  Eurydice_arr_c7
  to_hash0 =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_to_slice_shared_01(&decrypted));
  Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_5f1(&to_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार),
    ind_cpa_public_कुंजी_hash,
    uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_to_slice_shared_17(&to_hash0));
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 shared_secret0 = uu____1.fst;
  Eurydice_borrow_slice_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_af to_hash = libcrux_ml_kem_utils_into_padded_array_66(implicit_rejection_मूल्य);
  Eurydice_mut_borrow_slice_u8
  uu____2 =
    Eurydice_array_to_subslice_from_mut_5f2(&to_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार);
  Eurydice_slice_copy(uu____2, libcrux_ml_kem_types_as_ref_c1_52(ciphertext), uint8_t);
  Eurydice_arr_ec
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_array_to_slice_shared_81(&to_hash));
  Eurydice_arr_2b
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_d5(ind_cpa_public_कुंजी,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_slice_u8
  uu____3 = Eurydice_array_to_slice_shared_01(&implicit_rejection_shared_secret);
  Eurydice_arr_ec
  implicit_rejection_shared_secret0 =
    libcrux_ml_kem_variant_kdf_39_52(uu____3,
      libcrux_ml_kem_types_as_slice_a9_52(ciphertext));
  Eurydice_arr_ec
  shared_secret =
    libcrux_ml_kem_variant_kdf_39_52(shared_secret0,
      libcrux_ml_kem_types_as_slice_a9_52(ciphertext));
  Eurydice_borrow_slice_u8 uu____4 = libcrux_ml_kem_types_as_ref_c1_52(ciphertext);
  वापस
    libcrux_ml_kem_constant_time_ops_compare_ciphertexts_select_shared_secret_in_constant_time(uu____4,
      Eurydice_array_to_slice_shared_06(&expected_ciphertext),
      Eurydice_array_to_slice_shared_01(&shared_secret),
      Eurydice_array_to_slice_shared_01(&implicit_rejection_shared_secret0));
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
अटल अंतरभूत Eurydice_arr_ec
libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_19(
  स्थिर Eurydice_arr_7d *private_कुंजी,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  वापस libcrux_ml_kem_ind_cca_decapsulate_fd(private_कुंजी, ciphertext);
}

/**
 Decapsulate ML-KEM 768

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
*/
अटल अंतरभूत Eurydice_arr_ec
libcrux_ml_kem_mlkem768_portable_decapsulate(
  स्थिर Eurydice_arr_7d *private_कुंजी,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  वापस libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_19(private_कुंजी, ciphertext);
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
अटल KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_variant_entropy_preprocess_39_13(Eurydice_borrow_slice_u8 randomness)
{
  Eurydice_arr_ec out = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_01(&out), randomness, uint8_t);
  वापस out;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.H_4a
with const generics
- K= 3
*/
अटल अंतरभूत Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_borrow_slice_u8 निवेश)
{
  वापस libcrux_ml_kem_hash_functions_portable_H(निवेश);
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
अटल KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_encapsulate_99(
  स्थिर Eurydice_arr_5f *public_कुंजी,
  स्थिर Eurydice_arr_ec *randomness
)
{
  Eurydice_arr_ec
  randomness0 =
    libcrux_ml_kem_variant_entropy_preprocess_39_13(Eurydice_array_to_slice_shared_01(randomness));
  Eurydice_arr_c7
  to_hash =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_to_slice_shared_01(&randomness0));
  Eurydice_mut_borrow_slice_u8
  uu____0 =
    Eurydice_array_to_subslice_from_mut_5f1(&to_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_आकार);
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_ec
  lvalue =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_to_slice_shared_ff(libcrux_ml_kem_types_as_slice_e6_3d(public_कुंजी)));
  Eurydice_slice_copy(uu____0, Eurydice_array_to_slice_shared_01(&lvalue), uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_to_slice_shared_17(&to_hash));
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_slice_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_2b
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_d5(Eurydice_array_to_slice_shared_ff(libcrux_ml_kem_types_as_slice_e6_3d(public_कुंजी)),
      &randomness0,
      pseudorandomness);
  Eurydice_arr_2b uu____2 = libcrux_ml_kem_types_from_19_52(ciphertext);
  वापस
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
अटल अंतरभूत tuple_f4
libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_26(
  स्थिर Eurydice_arr_5f *public_कुंजी,
  स्थिर Eurydice_arr_ec *randomness
)
{
  वापस libcrux_ml_kem_ind_cca_encapsulate_99(public_कुंजी, randomness);
}

/**
 Encapsulate ML-KEM 768

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an [`MlKem768PublicKey`] and [`SHARED_SECRET_SIZE`]
 bytes of `randomness`.
*/
अटल अंतरभूत tuple_f4
libcrux_ml_kem_mlkem768_portable_encapsulate(
  स्थिर Eurydice_arr_5f *public_कुंजी,
  Eurydice_arr_ec randomness
)
{
  वापस libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_26(public_कुंजी, &randomness);
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
अटल अंतरभूत Eurydice_arr_bb0 libcrux_ml_kem_ind_cpa_unpacked_default_70_68(व्योम)
{
  Eurydice_arr_bb0 lit;
  Eurydice_arr_9e repeat_expression[3U];
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    repeat_expression[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  स_नकल(lit.तथ्य, repeat_expression, (माप_प्रकार)3U * माप (Eurydice_arr_9e));
  वापस lit;
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
अटल KRML_MUSTINLINE Eurydice_arr_c7
libcrux_ml_kem_variant_cpa_keygen_seed_39_13(Eurydice_borrow_slice_u8 कुंजी_generation_seed)
{
  Eurydice_arr_fa0 seed = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d412(&seed,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)0U,
          .end = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_कुंजी_GENERATION_SEED_आकार
        }
      )),
    कुंजी_generation_seed,
    uint8_t);
  seed.तथ्य[LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_कुंजी_GENERATION_SEED_आकार] = (uint8_t)(माप_प्रकार)3U;
  वापस
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_to_slice_shared_b5(&seed));
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
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_39(व्योम **_, माप_प्रकार tupled_args)
{
  वापस libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.to_standard_domain
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_polynomial_to_standard_domain_ea(Eurydice_arr_d6 vector)
{
  वापस
    libcrux_ml_kem_vector_portable_montgomery_multiply_by_constant_b8(vector,
      LIBCRUX_ML_KEM_VECTOR_TRAITS_MONTGOMERY_R_SQUARED_MOD_FIELD_MODULUS);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_standard_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_polynomial_add_standard_error_reduce_ea(
  Eurydice_arr_9e *myself,
  स्थिर Eurydice_arr_9e *error
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार j = i;
    Eurydice_arr_d6
    coefficient_normal_form = libcrux_ml_kem_polynomial_to_standard_domain_ea(myself->तथ्य[j]);
    Eurydice_arr_d6
    योग = libcrux_ml_kem_vector_portable_add_b8(coefficient_normal_form, &error->तथ्य[j]);
    Eurydice_arr_d6 red = libcrux_ml_kem_vector_portable_barrett_reduce_b8(योग);
    myself->तथ्य[j] = red;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_polynomial_add_standard_error_reduce_d6_ea(
  Eurydice_arr_9e *self,
  स्थिर Eurydice_arr_9e *error
)
{
  libcrux_ml_kem_polynomial_add_standard_error_reduce_ea(self, error);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_matrix_compute_As_plus_e_68(
  Eurydice_arr_bb0 *t_as_ntt,
  स्थिर Eurydice_arr_c10 *matrix_A,
  स्थिर Eurydice_arr_bb0 *s_as_ntt,
  स्थिर Eurydice_arr_bb0 *error_as_ntt
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    स्थिर Eurydice_arr_bb0 *row = &matrix_A->तथ्य[i0];
    Eurydice_arr_9e uu____0 = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    t_as_ntt->तथ्य[i0] = uu____0;
    क्रम (माप_प्रकार i1 = (माप_प्रकार)0U; i1 < (माप_प्रकार)3U; i1++)
    {
      माप_प्रकार j = i1;
      स्थिर Eurydice_arr_9e *matrix_element = &row->तथ्य[j];
      Eurydice_arr_9e
      product = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(matrix_element, &s_as_ntt->तथ्य[j]);
      libcrux_ml_kem_polynomial_add_to_ring_element_d6_68(&t_as_ntt->तथ्य[i0], &product);
    }
    libcrux_ml_kem_polynomial_add_standard_error_reduce_d6_ea(&t_as_ntt->तथ्य[i0],
      &error_as_ntt->तथ्य[i0]);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(
  Eurydice_borrow_slice_u8 कुंजी_generation_seed,
  Eurydice_arr_bb0 *private_कुंजी,
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51 *public_कुंजी
)
{
  Eurydice_arr_c7 hashed = libcrux_ml_kem_variant_cpa_keygen_seed_39_13(कुंजी_generation_seed);
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_17(&hashed),
      (माप_प्रकार)32U,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 seed_for_A = uu____0.fst;
  Eurydice_borrow_slice_u8 seed_for_secret_and_error = uu____0.snd;
  Eurydice_arr_c10 *uu____1 = &public_कुंजी->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31 lvalue0 = libcrux_ml_kem_utils_into_padded_array_de(seed_for_A);
  libcrux_ml_kem_matrix_sample_matrix_A_91(uu____1, &lvalue0, true);
  Eurydice_arr_fa0
  prf_निवेश = libcrux_ml_kem_utils_into_padded_array_29(seed_for_secret_and_error);
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_bf(private_कुंजी,
      &prf_निवेश,
      0U);
  Eurydice_arr_bb0 arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_struct.तथ्य[i] =
      libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_39(&lvalue,
        i);
  }
  Eurydice_arr_bb0 error_as_ntt = arr_struct;
  libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_bf(&error_as_ntt,
    &prf_निवेश,
    domain_separator);
  libcrux_ml_kem_matrix_compute_As_plus_e_68(&public_कुंजी->t_as_ntt,
    &public_कुंजी->A,
    &private_कुंजी[0U],
    &error_as_ntt);
  Eurydice_arr_ec arr;
  स_नकल(arr.तथ्य, seed_for_A.ptr, (माप_प्रकार)32U * माप (uint8_t));
  Eurydice_arr_ec
  uu____2 =
    core_परिणाम_unwrap_26_39((
        KRML_CLITERAL(core_परिणाम_परिणाम_07){ .tag = core_परिणाम_Ok, .val = { .case_Ok = arr } }
      ));
  public_कुंजी->seed_for_A = uu____2;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.serialize_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल KRML_MUSTINLINE Eurydice_arr_b20
libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(स्थिर Eurydice_arr_9e *re)
{
  Eurydice_arr_b20 serialized = { .तथ्य = { 0U } };
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_IN_RING_ELEMENT; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_d6
    coefficient = libcrux_ml_kem_serialize_to_unsigned_field_modulus_ea(re->तथ्य[i0]);
    Eurydice_arr_94 bytes = libcrux_ml_kem_vector_portable_serialize_12_b8(coefficient);
    Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d415(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = (माप_प्रकार)24U * i0,
            .end = (माप_प्रकार)24U * i0 + (माप_प्रकार)24U
          }
        )),
      Eurydice_array_to_slice_shared_ed(&bytes),
      uint8_t);
  }
  वापस serialized;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cpa_serialize_vector_68(
  स्थिर Eurydice_arr_bb0 *कुंजी,
  Eurydice_mut_borrow_slice_u8 out
)
{
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    माप_प्रकार i0 = i;
    Eurydice_arr_9e re = कुंजी->तथ्य[i0];
    Eurydice_mut_borrow_slice_u8
    uu____0 =
      Eurydice_slice_subslice_mut_c8(out,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = i0 * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT,
            .end = (i0 + (माप_प्रकार)1U) * LIBCRUX_ML_KEM_CONSTANTS_BYTES_PER_RING_ELEMENT
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_b20 lvalue = libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(&re);
    Eurydice_slice_copy(uu____0, Eurydice_array_to_slice_shared_a9(&lvalue), uint8_t);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cpa_serialize_public_कुंजी_mut_b6(
  स्थिर Eurydice_arr_bb0 *t_as_ntt,
  Eurydice_borrow_slice_u8 seed_for_a,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_vector_68(t_as_ntt,
    Eurydice_array_to_subslice_mut_d416(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)0U,
          .end = libcrux_ml_kem_constants_ranked_bytes_per_ring_element((माप_प्रकार)3U)
        }
      )));
  Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_5f4(serialized,
      libcrux_ml_kem_constants_ranked_bytes_per_ring_element((माप_प्रकार)3U)),
    seed_for_a,
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
अटल KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cpa_serialize_public_कुंजी_b6(
  स्थिर Eurydice_arr_bb0 *t_as_ntt,
  Eurydice_borrow_slice_u8 seed_for_a
)
{
  Eurydice_arr_5f public_कुंजी_serialized = { .तथ्य = { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_public_कुंजी_mut_b6(t_as_ntt,
    seed_for_a,
    &public_कुंजी_serialized);
  वापस public_कुंजी_serialized;
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
अटल अंतरभूत libcrux_ml_kem_utils_extraction_helper_Keypair768
libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_कुंजी_30(
  स्थिर libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51 *public_कुंजी,
  स्थिर Eurydice_arr_bb0 *private_कुंजी
)
{
  Eurydice_arr_5f
  public_कुंजी_serialized =
    libcrux_ml_kem_ind_cpa_serialize_public_कुंजी_b6(&public_कुंजी->t_as_ntt,
      Eurydice_array_to_slice_shared_01(&public_कुंजी->seed_for_A));
  Eurydice_arr_0e secret_कुंजी_serialized = { .तथ्य = { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_vector_68(private_कुंजी,
    Eurydice_array_to_slice_mut_f4(&secret_कुंजी_serialized));
  वापस
    (
      KRML_CLITERAL(libcrux_ml_kem_utils_extraction_helper_Keypair768){
        .fst = secret_कुंजी_serialized,
        .snd = public_कुंजी_serialized
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
अटल KRML_MUSTINLINE libcrux_ml_kem_utils_extraction_helper_Keypair768
libcrux_ml_kem_ind_cpa_generate_keypair_30(Eurydice_borrow_slice_u8 कुंजी_generation_seed)
{
  Eurydice_arr_bb0 private_कुंजी = libcrux_ml_kem_ind_cpa_unpacked_default_70_68();
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51
  public_कुंजी = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68();
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(कुंजी_generation_seed,
    &private_कुंजी,
    &public_कुंजी);
  वापस libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_कुंजी_30(&public_कुंजी, &private_कुंजी);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_serialize_kem_secret_कुंजी_mut_52(
  Eurydice_borrow_slice_u8 private_कुंजी,
  Eurydice_borrow_slice_u8 public_कुंजी,
  Eurydice_borrow_slice_u8 implicit_rejection_मूल्य,
  Eurydice_arr_7d *serialized
)
{
  माप_प्रकार pointer = (माप_प्रकार)0U;
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = pointer,
          .end = pointer + private_कुंजी.meta
        }
      )),
    private_कुंजी,
    uint8_t);
  pointer += private_कुंजी.meta;
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d417(serialized,
      (KRML_CLITERAL(core_ops_range_Range_87){ .start = pointer, .end = pointer + public_कुंजी.meta })),
    public_कुंजी,
    uint8_t);
  pointer += public_कुंजी.meta;
  Eurydice_mut_borrow_slice_u8
  uu____0 =
    Eurydice_array_to_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = pointer,
          .end = pointer + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_आकार
        }
      ));
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_ec lvalue = libcrux_ml_kem_hash_functions_portable_H_4a_78(public_कुंजी);
  Eurydice_slice_copy(uu____0, Eurydice_array_to_slice_shared_01(&lvalue), uint8_t);
  pointer += LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_आकार;
  Eurydice_slice_copy(Eurydice_array_to_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = pointer,
          .end = pointer + implicit_rejection_मूल्य.meta
        }
      )),
    implicit_rejection_मूल्य,
    uint8_t);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.serialize_kem_secret_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SERIALIZED_KEY_LEN= 2400
*/
अटल KRML_MUSTINLINE Eurydice_arr_7d
libcrux_ml_kem_ind_cca_serialize_kem_secret_कुंजी_52(
  Eurydice_borrow_slice_u8 private_कुंजी,
  Eurydice_borrow_slice_u8 public_कुंजी,
  Eurydice_borrow_slice_u8 implicit_rejection_मूल्य
)
{
  Eurydice_arr_7d out = { .तथ्य = { 0U } };
  libcrux_ml_kem_ind_cca_serialize_kem_secret_कुंजी_mut_52(private_कुंजी,
    public_कुंजी,
    implicit_rejection_मूल्य,
    &out);
  वापस out;
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
अटल KRML_MUSTINLINE libcrux_ml_kem_mlkem768_Ml_Kem768_कुंजी_Pair
libcrux_ml_kem_ind_cca_generate_keypair_b8(स्थिर Eurydice_arr_c7 *randomness)
{
  Eurydice_borrow_slice_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_to_subslice_shared_d47(randomness,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)0U,
          .end = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_कुंजी_GENERATION_SEED_आकार
        }
      ));
  Eurydice_borrow_slice_u8
  implicit_rejection_मूल्य =
    Eurydice_array_to_subslice_from_shared_5f1(randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_कुंजी_GENERATION_SEED_आकार);
  libcrux_ml_kem_utils_extraction_helper_Keypair768
  uu____0 = libcrux_ml_kem_ind_cpa_generate_keypair_30(ind_cpa_keypair_randomness);
  Eurydice_arr_0e ind_cpa_private_कुंजी = uu____0.fst;
  Eurydice_arr_5f public_कुंजी = uu____0.snd;
  Eurydice_arr_7d
  secret_कुंजी_serialized =
    libcrux_ml_kem_ind_cca_serialize_kem_secret_कुंजी_52(Eurydice_array_to_slice_shared_f4(&ind_cpa_private_कुंजी),
      Eurydice_array_to_slice_shared_ff(&public_कुंजी),
      implicit_rejection_मूल्य);
  Eurydice_arr_7d private_कुंजी = libcrux_ml_kem_types_from_b2_79(secret_कुंजी_serialized);
  वापस
    libcrux_ml_kem_types_from_17_bc(private_कुंजी,
      libcrux_ml_kem_types_from_51_3d(public_कुंजी));
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
अटल अंतरभूत libcrux_ml_kem_mlkem768_Ml_Kem768_कुंजी_Pair
libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_e9(
  स्थिर Eurydice_arr_c7 *randomness
)
{
  वापस libcrux_ml_kem_ind_cca_generate_keypair_b8(randomness);
}

/**
 Generate ML-KEM 768 Key Pair
*/
अटल अंतरभूत libcrux_ml_kem_mlkem768_Ml_Kem768_कुंजी_Pair
libcrux_ml_kem_mlkem768_portable_generate_कुंजी_pair(Eurydice_arr_c7 randomness)
{
  वापस libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_e9(&randomness);
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
अटल KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_private_कुंजी_only_52(स्थिर Eurydice_arr_7d *private_कुंजी)
{
  Eurydice_arr_ec
  t =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_to_subslice_shared_d48(private_कुंजी,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .start = (माप_प्रकार)384U * (माप_प्रकार)3U,
            .end = (माप_प्रकार)768U * (माप_प्रकार)3U + (माप_प्रकार)32U
          }
        )));
  Eurydice_borrow_slice_u8
  expected =
    Eurydice_array_to_subslice_shared_d48(private_कुंजी,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)768U * (माप_प्रकार)3U + (माप_प्रकार)32U,
          .end = (माप_प्रकार)768U * (माप_प्रकार)3U + (माप_प्रकार)64U
        }
      ));
  वापस Eurydice_array_eq_slice_shared((माप_प्रकार)32U, &t, &expected, uint8_t, bool);
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
अटल KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_private_कुंजी_ba(
  स्थिर Eurydice_arr_7d *private_कुंजी,
  स्थिर Eurydice_arr_2b *_ciphertext
)
{
  वापस libcrux_ml_kem_ind_cca_validate_private_कुंजी_only_52(private_कुंजी);
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
अटल KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_private_कुंजी_d3(
  स्थिर Eurydice_arr_7d *private_कुंजी,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  वापस libcrux_ml_kem_ind_cca_validate_private_कुंजी_ba(private_कुंजी, ciphertext);
}

/**
 Validate a private key.

 Returns `true` if valid, and `false` otherwise.
*/
अटल अंतरभूत bool
libcrux_ml_kem_mlkem768_portable_validate_private_कुंजी(
  स्थिर Eurydice_arr_7d *private_कुंजी,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  वापस
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_private_कुंजी_d3(private_कुंजी,
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
अटल KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_private_कुंजी_only_3b(
  स्थिर Eurydice_arr_7d *private_कुंजी
)
{
  वापस libcrux_ml_kem_ind_cca_validate_private_कुंजी_only_52(private_कुंजी);
}

/**
 Validate the private key only.

 Returns `true` if valid, and `false` otherwise.
*/
अटल अंतरभूत bool
libcrux_ml_kem_mlkem768_portable_validate_private_कुंजी_only(स्थिर Eurydice_arr_7d *private_कुंजी)
{
  वापस
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_private_कुंजी_only_3b(private_कुंजी);
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
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_out_call_mut_0b_68(
  व्योम **_,
  माप_प्रकार tupled_args
)
{
  वापस libcrux_ml_kem_polynomial_ZERO_d6_ea();
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
अटल KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_out_68(
  Eurydice_borrow_slice_u8 public_कुंजी
)
{
  Eurydice_arr_bb0 arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_struct.तथ्य[i] =
      libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_out_call_mut_0b_68(&lvalue,
        i);
  }
  Eurydice_arr_bb0 deserialized_pk = arr_struct;
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(public_कुंजी, &deserialized_pk);
  वापस deserialized_pk;
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
अटल KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_public_कुंजी_b6(स्थिर Eurydice_arr_5f *public_कुंजी)
{
  Eurydice_arr_bb0
  deserialized_pk =
    libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_out_68(Eurydice_array_to_subslice_to_shared_210(public_कुंजी,
        libcrux_ml_kem_constants_ranked_bytes_per_ring_element((माप_प्रकार)3U)));
  Eurydice_arr_5f
  public_कुंजी_serialized =
    libcrux_ml_kem_ind_cpa_serialize_public_कुंजी_b6(&deserialized_pk,
      Eurydice_array_to_subslice_from_shared_5f2(public_कुंजी,
        libcrux_ml_kem_constants_ranked_bytes_per_ring_element((माप_प्रकार)3U)));
  वापस Eurydice_array_eq((माप_प्रकार)1184U, public_कुंजी, &public_कुंजी_serialized, uint8_t);
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
अटल KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_public_कुंजी_3b(
  स्थिर Eurydice_arr_5f *public_कुंजी
)
{
  वापस libcrux_ml_kem_ind_cca_validate_public_कुंजी_b6(public_कुंजी);
}

/**
 Validate a public key.

 Returns `true` if valid, and `false` otherwise.
*/
अटल अंतरभूत bool
libcrux_ml_kem_mlkem768_portable_validate_public_कुंजी(स्थिर Eurydice_arr_5f *public_कुंजी)
{
  वापस libcrux_ml_kem_ind_cca_instantiations_portable_validate_public_कुंजी_3b(public_कुंजी);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
प्रकार काष्ठा libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51_s
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51 ind_cpa_public_कुंजी;
  Eurydice_arr_ec public_कुंजी_hash;
}
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51;

प्रकार libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51
libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_Public_कुंजी_Unpacked;

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPrivateKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
प्रकार काष्ठा libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Private_कुंजी_Unpacked_51_s
{
  Eurydice_arr_bb0 ind_cpa_private_कुंजी;
  Eurydice_arr_ec implicit_rejection_मूल्य;
}
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Private_कुंजी_Unpacked_51;

प्रकार काष्ठा libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked_s
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Private_कुंजी_Unpacked_51 private_कुंजी;
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 public_कुंजी;
}
libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked;

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
अटल KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_unpacked_decapsulate_0c(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_ec
  decrypted =
    libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(&कुंजी_pair->private_कुंजी.ind_cpa_private_कुंजी,
      ciphertext);
  Eurydice_arr_c7
  to_hash0 =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_to_slice_shared_01(&decrypted));
  Eurydice_mut_borrow_slice_u8
  uu____0 =
    Eurydice_array_to_subslice_from_mut_5f1(&to_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार);
  Eurydice_slice_copy(uu____0,
    Eurydice_array_to_slice_shared_01(&कुंजी_pair->public_कुंजी.public_कुंजी_hash),
    uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_to_slice_shared_17(&to_hash0));
  Eurydice_borrow_slice_u8_x2
  uu____1 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_slice_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_af
  to_hash =
    libcrux_ml_kem_utils_into_padded_array_66(Eurydice_array_to_slice_shared_01(&कुंजी_pair->private_कुंजी.implicit_rejection_मूल्य));
  Eurydice_mut_borrow_slice_u8
  uu____2 =
    Eurydice_array_to_subslice_from_mut_5f2(&to_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार);
  Eurydice_slice_copy(uu____2, libcrux_ml_kem_types_as_ref_c1_52(ciphertext), uint8_t);
  Eurydice_arr_ec
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_array_to_slice_shared_81(&to_hash));
  Eurydice_arr_2b
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&कुंजी_pair->public_कुंजी.ind_cpa_public_कुंजी,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_slice_u8 uu____3 = libcrux_ml_kem_types_as_ref_c1_52(ciphertext);
  uint8_t
  selector =
    libcrux_ml_kem_constant_time_ops_compare_ciphertexts_in_constant_time(uu____3,
      Eurydice_array_to_slice_shared_06(&expected_ciphertext));
  वापस
    libcrux_ml_kem_constant_time_ops_select_shared_secret_in_constant_time(shared_secret,
      Eurydice_array_to_slice_shared_01(&implicit_rejection_shared_secret),
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
अटल KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_19(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  वापस libcrux_ml_kem_ind_cca_unpacked_decapsulate_0c(कुंजी_pair, ciphertext);
}

/**
 Decapsulate ML-KEM 768 (unpacked)

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an unpacked key pair of type [`MlKem768KeyPairUnpacked`]
 and an [`MlKem768Ciphertext`].
*/
अटल अंतरभूत Eurydice_arr_ec
libcrux_ml_kem_mlkem768_portable_unpacked_decapsulate(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *private_कुंजी,
  स्थिर Eurydice_arr_2b *ciphertext
)
{
  वापस
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_19(private_कुंजी,
      ciphertext);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.encaps_prepare
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
अटल अंतरभूत Eurydice_arr_c7
libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_13(
  Eurydice_borrow_slice_u8 randomness,
  Eurydice_borrow_slice_u8 pk_hash
)
{
  Eurydice_arr_c7 to_hash = libcrux_ml_kem_utils_into_padded_array_c9(randomness);
  Eurydice_slice_copy(Eurydice_array_to_subslice_from_mut_5f1(&to_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_आकार),
    pk_hash,
    uint8_t);
  वापस
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_to_slice_shared_17(&to_hash));
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
अटल KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_unpacked_encapsulate_a7(
  स्थिर libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *public_कुंजी,
  स्थिर Eurydice_arr_ec *randomness
)
{
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_13(Eurydice_array_to_slice_shared_01(randomness),
      Eurydice_array_to_slice_shared_01(&public_कुंजी->public_कुंजी_hash));
  Eurydice_borrow_slice_u8_x2
  uu____0 =
    Eurydice_slice_split_at(Eurydice_array_to_slice_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_आकार,
      uint8_t,
      Eurydice_borrow_slice_u8_x2);
  Eurydice_borrow_slice_u8 shared_secret = uu____0.fst;
  Eurydice_borrow_slice_u8 pseudorandomness = uu____0.snd;
  Eurydice_arr_2b
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&public_कुंजी->ind_cpa_public_कुंजी,
      randomness,
      pseudorandomness);
  Eurydice_arr_ec shared_secret_array = { .तथ्य = { 0U } };
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_01(&shared_secret_array),
    shared_secret,
    uint8_t);
  वापस
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
अटल KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_26(
  स्थिर libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *public_कुंजी,
  स्थिर Eurydice_arr_ec *randomness
)
{
  वापस libcrux_ml_kem_ind_cca_unpacked_encapsulate_a7(public_कुंजी, randomness);
}

/**
 Encapsulate ML-KEM 768 (unpacked)

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an unpacked public key of type [`MlKem768PublicKeyUnpacked`],
 the SHA3-256 hash of this public key, and [`SHARED_SECRET_SIZE`] bytes of `randomness`.
*/
अटल अंतरभूत tuple_f4
libcrux_ml_kem_mlkem768_portable_unpacked_encapsulate(
  स्थिर libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *public_कुंजी,
  Eurydice_arr_ec randomness
)
{
  वापस
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_26(public_कुंजी,
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
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_ind_cca_unpacked_transpose_a_closure_call_mut_b4_68(
  व्योम **_,
  माप_प्रकार tupled_args
)
{
  वापस libcrux_ml_kem_polynomial_ZERO_d6_ea();
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
अटल अंतरभूत Eurydice_arr_bb0
libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_22_68(व्योम **_, माप_प्रकार tupled_args)
{
  Eurydice_arr_bb0 arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_struct.तथ्य[i] =
      libcrux_ml_kem_ind_cca_unpacked_transpose_a_closure_call_mut_b4_68(&lvalue,
        i);
  }
  वापस arr_struct;
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.clone_c1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
अटल अंतरभूत Eurydice_arr_9e
libcrux_ml_kem_polynomial_clone_c1_ea(स्थिर Eurydice_arr_9e *self)
{
  वापस
    core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)16U,
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
अटल अंतरभूत Eurydice_arr_c10
libcrux_ml_kem_ind_cca_unpacked_transpose_a_68(Eurydice_arr_c10 ind_cpa_a)
{
  Eurydice_arr_c10 arr_struct;
  क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    व्योम *lvalue = (व्योम *)0U;
    arr_struct.तथ्य[i] = libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_22_68(&lvalue, i);
  }
  Eurydice_arr_c10 A = arr_struct;
  क्रम (माप_प्रकार i0 = (माप_प्रकार)0U; i0 < (माप_प्रकार)3U; i0++)
  {
    माप_प्रकार i1 = i0;
    क्रम (माप_प्रकार i = (माप_प्रकार)0U; i < (माप_प्रकार)3U; i++)
    {
      माप_प्रकार j = i;
      Eurydice_arr_9e uu____0 = libcrux_ml_kem_polynomial_clone_c1_ea(&ind_cpa_a.तथ्य[j].तथ्य[i1]);
      A.तथ्य[i1].तथ्य[j] = uu____0;
    }
  }
  वापस A;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_unpacked_generate_keypair_b8(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *out
)
{
  Eurydice_borrow_slice_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_to_subslice_shared_d47(&randomness,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .start = (माप_प्रकार)0U,
          .end = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_कुंजी_GENERATION_SEED_आकार
        }
      ));
  Eurydice_borrow_slice_u8
  implicit_rejection_मूल्य =
    Eurydice_array_to_subslice_from_shared_5f1(&randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_कुंजी_GENERATION_SEED_आकार);
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(ind_cpa_keypair_randomness,
    &out->private_कुंजी.ind_cpa_private_कुंजी,
    &out->public_कुंजी.ind_cpa_public_कुंजी);
  Eurydice_arr_c10
  A = libcrux_ml_kem_ind_cca_unpacked_transpose_a_68(out->public_कुंजी.ind_cpa_public_कुंजी.A);
  out->public_कुंजी.ind_cpa_public_कुंजी.A = A;
  Eurydice_arr_5f
  pk_serialized =
    libcrux_ml_kem_ind_cpa_serialize_public_कुंजी_b6(&out->public_कुंजी.ind_cpa_public_कुंजी.t_as_ntt,
      Eurydice_array_to_slice_shared_01(&out->public_कुंजी.ind_cpa_public_कुंजी.seed_for_A));
  Eurydice_arr_ec
  uu____0 =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_to_slice_shared_ff(&pk_serialized));
  out->public_कुंजी.public_कुंजी_hash = uu____0;
  Eurydice_arr_ec arr;
  स_नकल(arr.तथ्य, implicit_rejection_मूल्य.ptr, (माप_प्रकार)32U * माप (uint8_t));
  Eurydice_arr_ec
  uu____1 =
    core_परिणाम_unwrap_26_39((
        KRML_CLITERAL(core_परिणाम_परिणाम_07){ .tag = core_परिणाम_Ok, .val = { .case_Ok = arr } }
      ));
  out->private_कुंजी.implicit_rejection_मूल्य = uu____1;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_e9(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *out
)
{
  libcrux_ml_kem_ind_cca_unpacked_generate_keypair_b8(randomness, out);
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
अटल अंतरभूत व्योम
libcrux_ml_kem_mlkem768_portable_unpacked_generate_कुंजी_pair_mut(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_e9(randomness,
    कुंजी_pair);
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
अटल KRML_MUSTINLINE libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51
libcrux_ml_kem_ind_cca_unpacked_default_30_68(व्योम)
{
  वापस
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51){
        .ind_cpa_public_कुंजी = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68(),
        .public_कुंजी_hash = { .तथ्य = { 0U } }
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
अटल KRML_MUSTINLINE libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked
libcrux_ml_kem_ind_cca_unpacked_default_7b_68(व्योम)
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Private_कुंजी_Unpacked_51
  uu____0 =
    {
      .ind_cpa_private_कुंजी = libcrux_ml_kem_ind_cpa_unpacked_default_70_68(),
      .implicit_rejection_मूल्य = { .तथ्य = { 0U } }
    };
  वापस
    (
      KRML_CLITERAL(libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked){
        .private_कुंजी = uu____0,
        .public_कुंजी = libcrux_ml_kem_ind_cca_unpacked_default_30_68()
      }
    );
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
अटल अंतरभूत libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked
libcrux_ml_kem_mlkem768_portable_unpacked_generate_कुंजी_pair(Eurydice_arr_c7 randomness)
{
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked
  कुंजी_pair = libcrux_ml_kem_ind_cca_unpacked_default_7b_68();
  libcrux_ml_kem_mlkem768_portable_unpacked_generate_कुंजी_pair_mut(randomness, &कुंजी_pair);
  वापस कुंजी_pair;
}

/**
 Create a new, empty unpacked key.
*/
अटल अंतरभूत libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked
libcrux_ml_kem_mlkem768_portable_unpacked_init_कुंजी_pair(व्योम)
{
  वापस libcrux_ml_kem_ind_cca_unpacked_default_7b_68();
}

/**
 Create a new, empty unpacked public key.
*/
अटल अंतरभूत libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51
libcrux_ml_kem_mlkem768_portable_unpacked_init_public_कुंजी(व्योम)
{
  वापस libcrux_ml_kem_ind_cca_unpacked_default_30_68();
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_unpacked_कुंजियाँ_from_private_कुंजी_01(
  स्थिर Eurydice_arr_7d *private_कुंजी,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair
)
{
  Eurydice_borrow_slice_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_private_कुंजी_64(Eurydice_array_to_slice_shared_51(private_कुंजी));
  Eurydice_borrow_slice_u8 ind_cpa_secret_कुंजी = uu____0.fst;
  Eurydice_borrow_slice_u8 ind_cpa_public_कुंजी = uu____0.snd;
  Eurydice_borrow_slice_u8 ind_cpa_public_कुंजी_hash = uu____0.thd;
  Eurydice_borrow_slice_u8 implicit_rejection_मूल्य = uu____0.f3;
  libcrux_ml_kem_ind_cpa_deserialize_vector_68(ind_cpa_secret_कुंजी,
    &कुंजी_pair->private_कुंजी.ind_cpa_private_कुंजी);
  libcrux_ml_kem_ind_cpa_build_unpacked_public_कुंजी_mut_05(ind_cpa_public_कुंजी,
    &कुंजी_pair->public_कुंजी.ind_cpa_public_कुंजी);
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_01(&कुंजी_pair->public_कुंजी.public_कुंजी_hash),
    ind_cpa_public_कुंजी_hash,
    uint8_t);
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_01(&कुंजी_pair->private_कुंजी.implicit_rejection_मूल्य),
    implicit_rejection_मूल्य,
    uint8_t);
  Eurydice_slice_copy(Eurydice_array_to_slice_mut_01(&कुंजी_pair->public_कुंजी.ind_cpa_public_कुंजी.seed_for_A),
    Eurydice_slice_subslice_from_shared_6d(ind_cpa_public_कुंजी, (माप_प्रकार)1152U),
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_private_कुंजी_71(
  स्थिर Eurydice_arr_7d *private_कुंजी,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair
)
{
  libcrux_ml_kem_ind_cca_unpacked_कुंजियाँ_from_private_कुंजी_01(private_कुंजी, कुंजी_pair);
}

/**
 Get an unpacked key from a private key.
*/
अटल अंतरभूत व्योम
libcrux_ml_kem_mlkem768_portable_unpacked_कुंजी_pair_from_private_mut(
  स्थिर Eurydice_arr_7d *private_कुंजी,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_private_कुंजी_71(private_कुंजी,
    कुंजी_pair);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_unpacked_serialized_private_कुंजी_mut_11_21(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *self,
  Eurydice_arr_7d *serialized
)
{
  libcrux_ml_kem_utils_extraction_helper_Keypair768
  uu____0 =
    libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_कुंजी_30(&self->public_कुंजी.ind_cpa_public_कुंजी,
      &self->private_कुंजी.ind_cpa_private_कुंजी);
  Eurydice_arr_0e ind_cpa_private_कुंजी = uu____0.fst;
  Eurydice_arr_5f ind_cpa_public_कुंजी = uu____0.snd;
  libcrux_ml_kem_ind_cca_serialize_kem_secret_कुंजी_mut_52(Eurydice_array_to_slice_shared_f4(&ind_cpa_private_कुंजी),
    Eurydice_array_to_slice_shared_ff(&ind_cpa_public_कुंजी),
    Eurydice_array_to_slice_shared_01(&self->private_कुंजी.implicit_rejection_मूल्य),
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
अटल KRML_MUSTINLINE Eurydice_arr_7d
libcrux_ml_kem_ind_cca_unpacked_serialized_private_कुंजी_11_21(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *self
)
{
  Eurydice_arr_7d sk = libcrux_ml_kem_types_default_d3_79();
  libcrux_ml_kem_ind_cca_unpacked_serialized_private_कुंजी_mut_11_21(self, &sk);
  वापस sk;
}

/**
 Get the serialized private key.
*/
अटल अंतरभूत Eurydice_arr_7d
libcrux_ml_kem_mlkem768_portable_unpacked_कुंजी_pair_serialized_private_कुंजी(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair
)
{
  वापस libcrux_ml_kem_ind_cca_unpacked_serialized_private_कुंजी_11_21(कुंजी_pair);
}

/**
 Get the serialized private key.
*/
अटल अंतरभूत व्योम
libcrux_ml_kem_mlkem768_portable_unpacked_कुंजी_pair_serialized_private_कुंजी_mut(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair,
  Eurydice_arr_7d *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_private_कुंजी_mut_11_21(कुंजी_pair, serialized);
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
अटल KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cca_unpacked_serialized_dd_b6(
  स्थिर libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *self
)
{
  वापस
    libcrux_ml_kem_types_from_51_3d(libcrux_ml_kem_ind_cpa_serialize_public_कुंजी_b6(&self->ind_cpa_public_कुंजी.t_as_ntt,
        Eurydice_array_to_slice_shared_01(&self->ind_cpa_public_कुंजी.seed_for_A)));
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
अटल KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cca_unpacked_serialized_public_कुंजी_11_b6(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *self
)
{
  वापस libcrux_ml_kem_ind_cca_unpacked_serialized_dd_b6(&self->public_कुंजी);
}

/**
 Get the serialized public key.
*/
अटल अंतरभूत Eurydice_arr_5f
libcrux_ml_kem_mlkem768_portable_unpacked_कुंजी_pair_serialized_public_कुंजी(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair
)
{
  वापस libcrux_ml_kem_ind_cca_unpacked_serialized_public_कुंजी_11_b6(कुंजी_pair);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(
  स्थिर libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *self,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_public_कुंजी_mut_b6(&self->ind_cpa_public_कुंजी.t_as_ntt,
    Eurydice_array_to_slice_shared_01(&self->ind_cpa_public_कुंजी.seed_for_A),
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_unpacked_serialized_public_कुंजी_mut_11_b6(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *self,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(&self->public_कुंजी, serialized);
}

/**
 Get the serialized public key.
*/
अटल अंतरभूत व्योम
libcrux_ml_kem_mlkem768_portable_unpacked_कुंजी_pair_serialized_public_कुंजी_mut(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_public_कुंजी_mut_11_b6(कुंजी_pair, serialized);
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
अटल अंतरभूत libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51
libcrux_ml_kem_ind_cpa_unpacked_clone_91_68(
  स्थिर libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51 *self
)
{
  Eurydice_arr_bb0
  uu____0 =
    core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)3U,
      &self->t_as_ntt,
      Eurydice_arr_9e,
      Eurydice_arr_bb0);
  Eurydice_arr_ec
  uu____1 =
    core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)32U,
      &self->seed_for_A,
      uint8_t,
      Eurydice_arr_ec);
  वापस
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51){
        .t_as_ntt = uu____0,
        .seed_for_A = uu____1,
        .A = core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)3U,
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
अटल अंतरभूत libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51
libcrux_ml_kem_ind_cca_unpacked_clone_d7_68(
  स्थिर libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *self
)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_Public_कुंजी_Unpacked_51
  uu____0 = libcrux_ml_kem_ind_cpa_unpacked_clone_91_68(&self->ind_cpa_public_कुंजी);
  वापस
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51){
        .ind_cpa_public_कुंजी = uu____0,
        .public_कुंजी_hash = core_array__core__clone__Clone_for__T__N___clone((माप_प्रकार)32U,
          &self->public_कुंजी_hash,
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
अटल KRML_MUSTINLINE स्थिर
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51
*libcrux_ml_kem_ind_cca_unpacked_public_कुंजी_11_68(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *self
)
{
  वापस &self->public_कुंजी;
}

/**
 Get the unpacked public key.
*/
अटल अंतरभूत व्योम
libcrux_ml_kem_mlkem768_portable_unpacked_public_कुंजी(
  स्थिर libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_कुंजी_Pair_Unpacked *कुंजी_pair,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *pk
)
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51
  uu____0 =
    libcrux_ml_kem_ind_cca_unpacked_clone_d7_68(libcrux_ml_kem_ind_cca_unpacked_public_कुंजी_11_68(कुंजी_pair));
  pk[0U] = uu____0;
}

/**
 Get the serialized public key.
*/
अटल अंतरभूत व्योम
libcrux_ml_kem_mlkem768_portable_unpacked_serialized_public_कुंजी(
  स्थिर libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *public_कुंजी,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(public_कुंजी, serialized);
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_unpacked_unpack_public_कुंजी_22(
  स्थिर Eurydice_arr_5f *public_कुंजी,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *unpacked_public_कुंजी
)
{
  Eurydice_borrow_slice_u8
  uu____0 = Eurydice_array_to_subslice_to_shared_210(public_कुंजी, (माप_प्रकार)1152U);
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(uu____0,
    &unpacked_public_कुंजी->ind_cpa_public_कुंजी.t_as_ntt);
  unpacked_public_कुंजी->ind_cpa_public_कुंजी.seed_for_A =
    libcrux_ml_kem_utils_into_padded_array_ce(Eurydice_array_to_subslice_from_shared_5f2(public_कुंजी,
        (माप_प्रकार)1152U));
  Eurydice_arr_c10 *uu____2 = &unpacked_public_कुंजी->ind_cpa_public_कुंजी.A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31
  lvalue =
    libcrux_ml_kem_utils_into_padded_array_de(Eurydice_array_to_subslice_from_shared_5f2(public_कुंजी,
        (माप_प्रकार)1152U));
  libcrux_ml_kem_matrix_sample_matrix_A_91(uu____2, &lvalue, false);
  Eurydice_arr_ec
  uu____3 =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_to_slice_shared_ff(libcrux_ml_kem_types_as_slice_e6_3d(public_कुंजी)));
  unpacked_public_कुंजी->public_कुंजी_hash = uu____3;
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
अटल KRML_MUSTINLINE व्योम
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_public_कुंजी_d3(
  स्थिर Eurydice_arr_5f *public_कुंजी,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *unpacked_public_कुंजी
)
{
  libcrux_ml_kem_ind_cca_unpacked_unpack_public_कुंजी_22(public_कुंजी, unpacked_public_कुंजी);
}

/**
 Get the unpacked public key.
*/
अटल अंतरभूत व्योम
libcrux_ml_kem_mlkem768_portable_unpacked_unpacked_public_कुंजी(
  स्थिर Eurydice_arr_5f *public_कुंजी,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_Public_कुंजी_Unpacked_51 *unpacked_public_कुंजी
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_public_कुंजी_d3(public_कुंजी,
    unpacked_public_कुंजी);
}

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#घोषणा libcrux_mlkem768_portable_H_DEFINED
#पूर्ण_अगर /* libcrux_mlkem768_portable_H */


/* rename some types to be a bit more ergonomic */

/* ML-KEM 768 */
प्रकार Eurydice_arr_c7 libcrux_mlkem768_keypair_rnd;
प्रकार Eurydice_arr_ec libcrux_mlkem768_enc_rnd;
प्रकार libcrux_ml_kem_mlkem768_Ml_Kem768_कुंजी_Pair libcrux_mlkem768_keypair;
प्रकार Eurydice_arr_5f libcrux_mlkem768_pk;
प्रकार Eurydice_arr_7d libcrux_mlkem768_sk;
प्रकार Eurydice_arr_2b libcrux_mlkem768_ciphertext;
प्रकार tuple_f4 libcrux_mlkem768_enc_परिणाम;
प्रकार Eurydice_arr_ec libcrux_mlkem768_dec_परिणाम;
/* ML-DSA 44 */
प्रकार Eurydice_arr_ec libcrux_mldsa44_keypair_rnd;
प्रकार libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_कुंजी_Pair
    libcrux_mldsa44_keypair;
प्रकार Eurydice_arr_10 libcrux_mldsa44_sk;
प्रकार Eurydice_arr_02 libcrux_mldsa44_pk;
प्रकार Eurydice_borrow_slice_u8 libcrux_mldsa44_message;
प्रकार Eurydice_arr_ec libcrux_mldsa44_sign_rnd;
प्रकार core_परिणाम_परिणाम_48 libcrux_mldsa44_sign_परिणाम;
प्रकार core_परिणाम_परिणाम_41 libcrux_mldsa44_verify_परिणाम;
प्रकार Eurydice_arr_85 libcrux_mldsa44_signature;
/* ML-DSA 65 */
प्रकार Eurydice_arr_ec libcrux_mldsa65_keypair_rnd;
प्रकार libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_कुंजी_Pair
    libcrux_mldsa65_keypair;
प्रकार Eurydice_arr_24 libcrux_mldsa65_sk;
प्रकार Eurydice_arr_29 libcrux_mldsa65_pk;
प्रकार Eurydice_borrow_slice_u8 libcrux_mldsa65_message;
प्रकार Eurydice_arr_ec libcrux_mldsa65_sign_rnd;
प्रकार core_परिणाम_परिणाम_8c libcrux_mldsa65_sign_परिणाम;
प्रकार core_परिणाम_परिणाम_41 libcrux_mldsa65_verify_परिणाम;
प्रकार Eurydice_arr_0c libcrux_mldsa65_signature;
/* ML-DSA 87 */
प्रकार Eurydice_arr_ec libcrux_mldsa87_keypair_rnd;
प्रकार libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_कुंजी_Pair
    libcrux_mldsa87_keypair;
प्रकार Eurydice_arr_e2 libcrux_mldsa87_sk;
प्रकार Eurydice_arr_43 libcrux_mldsa87_pk;
प्रकार Eurydice_borrow_slice_u8 libcrux_mldsa87_message;
प्रकार Eurydice_arr_ec libcrux_mldsa87_sign_rnd;
प्रकार core_परिणाम_परिणाम_8b libcrux_mldsa87_sign_परिणाम;
प्रकार core_परिणाम_परिणाम_41 libcrux_mldsa87_verify_परिणाम;
प्रकार Eurydice_arr_93 libcrux_mldsa87_signature;

#घोषणा LIBCRUX_परिणाम_OK	core_परिणाम_Ok

