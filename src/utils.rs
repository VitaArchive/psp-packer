#![allow(unused)]
use std::slice;

use crate::error::Error;

pub fn gzip_max_compressed_size(len_src: usize) -> usize {
    let num_16k_block = len_src.div_ceil(16384);

    num_16k_block + 6 + (num_16k_block * 5) + 18
}

#[track_caller]
pub fn rand() -> rapidhash::RapidRng {
    use core::hash::BuildHasher;

    let hc64 = std::hash::RandomState::new().hash_one(core::panic::Location::caller());
    let seed_vec = hc64.to_le_bytes().into_iter().chain(0u8..16).collect::<Vec<u8>>();
    let seed: [u8; 24] = seed_vec.as_slice().try_into().unwrap();
    rand::SeedableRng::from_seed(seed)
}


pub trait TryFromBytes: Sized {
    fn validate(src: &Self) -> Result<&Self, Error>;

    #[doc(hidden)]
    #[inline]
    fn validate_mut(src: &mut Self) -> Result<&mut Self, Error> {
        Self::validate(src)?;
        Ok(src)
    }

    #[inline]
    #[must_use = "has no side effects"]
    fn from_bytes(src: &[u8]) -> Result<Self, Error> {
        let size = size_of::<Self>();
        split_bytes(src, size).and_then(|(head, _rest)| {
            // Safety: this cast and dereference are made sound by the length
            // check done in `split_bytes`.
            let res = unsafe {
                let ptr = head.as_ptr().cast::<Self>();

                if ptr.is_aligned() {
                    ptr.read()
                } else {
                    ptr.read_unaligned()
                }
            };
            Self::validate(&res)?;
            Ok(res)
        })
    }

    #[inline]
    #[must_use = "has no side effects"]
    fn from_bytes_with_elems(src: &[u8], count: usize) -> Result<Box<[Self]>, Error> {
        let expected_len = size_of::<Self>() * count;
        split_bytes(src, expected_len).and_then(|(head, _rest)| {
            let mut vec = Vec::with_capacity(count);

            for i in 0..count {
                let ptr = head.as_ptr().cast::<Self>().wrapping_add(i);
                let item = unsafe {
                    if ptr.is_aligned() {
                        ptr.read()
                    } else {
                        ptr.read_unaligned()
                    }
                };
                Self::validate(&item)?;
                vec.push(item);
            }
            Ok(vec.into_boxed_slice())
        })
    }


    #[inline]
    #[must_use = "has no side effects"]
    fn ref_from_bytes(src: &[u8]) -> Result<&Self, Error> {
        let size = size_of::<Self>();

        split_bytes(src, size).and_then(|(head, _rest)| {
            let ptr = head.as_ptr().cast::<Self>();
            if !ptr.is_aligned() {
                return Err(Error::Alignment {
                    align: align_of::<Self>(),
                    addr: ptr.addr(),
                });
            }

            // Safety: this cast and dereference are made sound by the length
            // check done in `split_bytes` and the alignment check above.
            let res = unsafe { &*ptr };
            Self::validate(res)
        })
    }

    #[inline]
    #[must_use = "has no side effects"]
    fn ref_from_bytes_with_elems(src: &[u8], count: usize) -> Result<&[Self], Error> {
        let expected_len = size_of::<Self>() * count;

        split_bytes(src, expected_len).and_then(|(head, _rest)| {
            let ptr = head.as_ptr().cast::<Self>();
            if !ptr.is_aligned() {
                return Err(Error::Alignment {
                    align: align_of::<Self>(),
                    addr: ptr.addr(),
                });
            }

            // Safety: this cast and dereference are made sound by the length
            // check done in `split_bytes` and the alignment check above.
            let res = unsafe { slice::from_raw_parts(ptr, count) };
            for r in res {
                Self::validate(r)?;
            }
            Ok(res)
        })
    }

    #[inline]
    #[must_use = "has no side effects"]
    fn mut_from_bytes(src: &mut [u8]) -> Result<&mut Self, Error> {
        let size = size_of::<Self>();

        split_mut_bytes(src, size).and_then(|(head, _rest)| {
            let ptr = head.as_mut_ptr().cast::<Self>();
            if !ptr.is_aligned() {
                return Err(Error::Alignment {
                    align: align_of::<Self>(),
                    addr: ptr.addr(),
                });
            }
            // Safety: this cast and dereference are made sound by the length
            // check done in `split_mut_bytes` and the alignment check above.
            let res = unsafe { &mut *ptr };

            Self::validate_mut(res)
        })
    }

    #[inline]
    #[must_use = "has no side effects"]
    fn mut_from_bytes_with_elems(src: &mut [u8], count: usize) -> Result<&mut [Self], Error> {
        let expected_len = size_of::<Self>() * count;

        split_mut_bytes(src, expected_len).and_then(|(head, _rest)| {
            let ptr = head.as_mut_ptr().cast::<Self>();
            if !ptr.is_aligned() {
                return Err(Error::Alignment {
                    align: align_of::<Self>(),
                    addr: ptr.addr(),
                });
            }
            // Safety: this cast and dereference are made sound by the length
            // check done in `split_mut_bytes` and the alignment check above.
            let res = unsafe { slice::from_raw_parts_mut(ptr, count) };
            for r in res.iter() {
                Self::validate(r)?;
            }
            Ok(res)
        })
    }
}

pub trait AsBytes: Sized {
    #[inline]
    #[must_use = "has no side effects"]
    fn as_bytes(&self) -> &[u8] {
        let len = size_of_val(self);
        let slf: *const Self = self;

        // SAFETY:
        // - `slf.cast::<u8>()` is valid for reads for `len * size_of::<u8>()` many bytes because...
        //   - `slf` is the same pointer as `self`, and `self` is a reference which points to an
        //     object whose size is `len`. Thus...
        //     - The entire region of `len` bytes starting at `slf` is contained within a single
        //       allocation.
        //     - `slf` is non-null.
        //   - `slf` is trivially aligned to `align_of::<u8>() == 1`.
        // - `Self: IntoBytes` ensures that all of the bytes of `slf` are initialized.
        // - Since `slf` is derived from `self`, and `self` is an immutable reference, the only
        //   other references to this memory region that could exist are other immutable references,
        //   and those don't allow mutation. `Self: Immutable` prohibits types which contain
        //   `UnsafeCell`s, which are the only types for which this rule wouldn't be sufficient.
        // - The total size of the resulting slice is no larger than `isize::MAX` because no
        //   allocation produced by safe code can be larger than `isize::MAX`.
        unsafe { slice::from_raw_parts(slf.cast::<u8>(), len) }
    }

    #[inline]
    #[must_use = "has no side effects"]
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        let len = size_of_val(self);
        let slf: *mut Self = self;

        // SAFETY:
        // - `slf.cast::<u8>()` is valid for reads and writes for `len * size_of::<u8>()` many bytes
        //   because...
        //   - `slf` is the same pointer as `self`, and `self` is a reference which points to an
        //     object whose size is `len`. Thus...
        //     - The entire region of `len` bytes starting at `slf` is contained within a single
        //       allocation.
        //     - `slf` is non-null.
        //   - `slf` is trivially aligned to `align_of::<u8>() == 1`.
        // - `Self: IntoBytes` ensures that all of the bytes of `slf` are initialized.
        // - `Self: FromBytes` ensures that no write to this memory region could result in it
        //   containing an invalid `Self`.
        // - Since `slf` is derived from `self`, and `self` is a mutable reference, no other
        //   references to this memory region can exist.
        // - The total size of the resulting slice is no larger than `isize::MAX` because no
        //   allocation produced by safe code can be larger than `isize::MAX`.
        unsafe { slice::from_raw_parts_mut(slf.cast::<u8>(), len) }
    }
}

fn split_bytes(bytes: &[u8], expected_byte_len: usize) -> Result<(&[u8], &[u8]), Error> {
    bytes.split_at_checked(expected_byte_len).ok_or(Error::FromBytes {
        input_len: bytes.len(),
        expected_len: Some(expected_byte_len),
    })
}

fn split_mut_bytes(
    bytes: &mut [u8], expected_byte_len: usize,
) -> Result<(&mut [u8], &mut [u8]), Error> {
    let len = bytes.len();
    bytes.split_at_mut_checked(expected_byte_len).ok_or(Error::FromBytes {
        input_len: len,
        expected_len: Some(expected_byte_len),
    })
}
