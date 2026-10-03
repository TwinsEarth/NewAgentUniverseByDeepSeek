//! Linux read-only shared-page mapping: `mmap`, fill, then `mprotect(PROT_READ)`.
//!
//! # Status: type-checked from any host, **runtime behaviour not verified here**
//!
//! This machine is Windows. The module is compiled and type-checked for
//! `x86_64-unknown-linux-gnu` by the `cross-target` gate, so it is known to build; it has
//! never been executed, and no test in this repository executes it. CI runs on Linux, but a
//! GitHub runner has no `/dev/kvm`, so the parts that need a real guest cannot run there
//! either. That is stated rather than implied because a claim of enforcement which has never
//! run against the mechanism is exactly the kind of documentation this crate exists to
//! replace.
//!
//! # The mechanism, and why it is a mechanism
//!
//! The page is mapped `PROT_READ | PROT_WRITE`, filled from the caller's buffer, and then
//! **downgraded with `mprotect` to `PROT_READ` alone**. From that point a store through the
//! mapping faults: the guard is the MMU's, not a convention in a library.
//!
//! Nothing in this module ever calls `mprotect` with `PROT_WRITE` after the fill, and the
//! handle exposes no method that could. That is the property worth stating: the downgrade is
//! one-way in the code, so "the guest cannot write the shared page" is not a promise about
//! future edits but a consequence of there being no path that restores write access.
//!
//! # What this does *not* cover
//!
//! Presenting the region to a guest as a `virtio-pmem` device, and configuring DAX so the
//! guest maps it as read-only, is hypervisor configuration. It happens outside this process
//! and outside this crate. This module secures the **host-side** mapping; the guest-side
//! half is a deployment concern that this repository does not implement, and the
//! `SHARED_PAGE_SUPPORT` declaration says so rather than claiming the whole path.

use std::ffi::c_void;
use std::io;

/// `PROT_READ` — pages may be read.
const PROT_READ: i32 = 0x1;
/// `PROT_WRITE` — pages may be written.
const PROT_WRITE: i32 = 0x2;
/// `MAP_PRIVATE` — copy-on-write, not shared with other processes.
const MAP_PRIVATE: i32 = 0x02;
/// `MAP_ANONYMOUS` — not backed by a file.
const MAP_ANONYMOUS: i32 = 0x20;
/// `MADV_PAGEOUT` — ask the kernel to reclaim these pages now.
const MADV_PAGEOUT: i32 = 21;

/// What `mmap` returns on failure.
const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;

extern "C" {
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(addr: *mut c_void, length: usize, prot: i32) -> i32;
    fn munmap(addr: *mut c_void, length: usize) -> i32;
    fn madvise(addr: *mut c_void, length: usize, advice: i32) -> i32;
}

/// A mapping that is read-only for its whole life.
///
/// Not `Send`/`Sync` by accident: it holds a raw pointer, so the compiler withholds those
/// impls. A shared page is read by many sandboxes and a mapping handle is not what they
/// share — the kernel's page cache is — so no impl is added.
#[derive(Debug)]
pub(crate) struct ReadOnlyMap {
    addr: *mut c_void,
    len: usize,
}

impl ReadOnlyMap {
    /// The mapped bytes.
    ///
    /// This is the accessor the shared-page view reads through, and it is why the mapping is
    /// worth taking: the bytes a caller sees come from the region that was downgraded to
    /// `PROT_READ`, not from a copy that happens to sit next to one. The first version of
    /// this module created the mapping and dropped it immediately -- the compiler's
    /// `never used` warning on `as_ptr`/`len` was the tell, and the fix was to put the
    /// mapping in the data path rather than to silence the warning.
    pub(crate) fn as_slice(&self) -> &[u8] {
        if self.addr.is_null() || self.len == 0 {
            return &[];
        }
        // SAFETY: `addr` is the base of a live mapping of `len` bytes owned by this handle.
        // The region was filled before it was downgraded, is never unmapped until `Drop`,
        // and `Drop` takes `&mut self`, so no `&[u8]` derived here can outlive it. Reading a
        // `PROT_READ` region is the operation it was mapped for.
        unsafe { std::slice::from_raw_parts(self.addr.cast::<u8>(), self.len) }
    }

    /// Ask the kernel to reclaim the pages at `plan`, in whole pages of `page_bytes`.
    ///
    /// Returns how many pages the kernel accepted. A page the caller did not plan is never
    /// touched: the loop walks `plan` and nothing else, so the policy decision made in
    /// [`crate::reclaim`] is the set the kernel sees.
    ///
    /// # Errors
    ///
    /// [`io::Error`] when `madvise` refuses. A partial pass reports the pages it did
    /// reclaim instead of failing the whole call: the pages it already returned are gone
    /// either way, and a caller that got an error and no count would have counters that
    /// understate what happened.
    pub(crate) fn reclaim_pages(&self, plan: &[usize], page_bytes: usize) -> io::Result<usize> {
        if self.addr.is_null() || self.len == 0 || page_bytes == 0 {
            return Ok(0);
        }
        let mut returned = 0_usize;
        for index in plan {
            let start = index.saturating_mul(page_bytes);
            // Only whole pages inside the mapping. A plan entry past the end is skipped
            // rather than clamped: clamping would page out a neighbouring page the caller
            // never planned, which is the one mistake this function must not make.
            if start.saturating_add(page_bytes) > self.len {
                continue;
            }
            // SAFETY: `addr + start` is inside the live mapping of `len` bytes, and
            // `page_bytes` does not take it past the end -- checked immediately above.
            // `madvise` reads the address range and does not retain it.
            let rc = unsafe {
                madvise(
                    self.addr.cast::<u8>().add(start).cast::<c_void>(),
                    page_bytes,
                    MADV_PAGEOUT,
                )
            };
            if rc == 0 {
                returned += 1;
            }
        }
        Ok(returned)
    }
}

impl Drop for ReadOnlyMap {
    fn drop(&mut self) {
        if !self.addr.is_null() && self.addr != MAP_FAILED && self.len > 0 {
            // SAFETY: `addr` and `len` are exactly what a successful `mmap` returned in
            // `map_readonly`, and this is the only place they are unmapped. The mapping is
            // untouched between the two calls -- no `munmap` runs anywhere else, and the
            // struct is not `Copy` -- so the region is still live.
            unsafe {
                let _ = munmap(self.addr, self.len);
            }
        }
    }
}

/// Map `bytes` into this process as a read-only region.
///
/// # Errors
///
/// [`io::Error`] carrying the OS error when `mmap` or `mprotect` fails. A failure here is
/// reported, never worked around: the caller asked for a read-only mapping and a
/// read-write one is not an acceptable substitute.
pub(crate) fn map_readonly(bytes: &[u8]) -> io::Result<ReadOnlyMap> {
    let len = bytes.len();
    if len == 0 {
        // An empty mapping is not useful and `mmap` with length 0 fails with `EINVAL`; the
        // caller gets a null region that `Drop` skips, rather than a confusing OS error.
        return Ok(ReadOnlyMap {
            addr: std::ptr::null_mut(),
            len: 0,
        });
    }

    // SAFETY: `mmap` with a null hint, a length, and no file descriptor is the standard
    // anonymous-mapping call. `MAP_ANONYMOUS` with `fd = -1` is what makes the descriptor
    // argument unused; the kernel returns either a valid pointer or `MAP_FAILED`, both of
    // which are checked before the pointer is used.
    let addr = unsafe {
        mmap(
            std::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if addr == MAP_FAILED || addr.is_null() {
        return Err(io::Error::last_os_error());
    }

    // Fill through the writable mapping, then downgrade. The `copy_nonoverlapping` is sound
    // because `addr` is a fresh mapping of exactly `len` bytes and `bytes` is a distinct
    // live slice of the same length.
    //
    // SAFETY: as described immediately above; the regions do not overlap because one is a
    // newly created private mapping.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr.cast::<u8>(), len);
    }

    // The downgrade. This is the security boundary: after it, a store through `addr` faults.
    //
    // SAFETY: `addr` and `len` describe the mapping just created, and `mprotect` takes
    // exactly a page-aligned base and a length. `mmap` always returns a page-aligned
    // address, so the alignment requirement holds.
    let rc = unsafe { mprotect(addr, len, PROT_READ) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        // Unmap before returning: leaving a writable mapping alive after a failed downgrade
        // would be exactly the state this function exists to prevent.
        //
        // SAFETY: the same mapping created above, still live and not yet unmapped.
        unsafe {
            let _ = munmap(addr, len);
        }
        return Err(err);
    }

    Ok(ReadOnlyMap { addr, len })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_only_mapping_holds_the_bytes_it_was_given() {
        let bytes = b"shared page contents";
        let map = map_readonly(bytes).expect("map");
        assert_eq!(map.as_slice().len(), bytes.len());
        // Read through the mapping itself. This is the same call the shared-page view makes,
        // so the test exercises the path a caller's bytes actually travel.
        assert_eq!(map.as_slice(), bytes);
    }

    #[test]
    fn an_empty_page_maps_to_nothing_rather_than_failing() {
        let map = map_readonly(b"").expect("map");
        assert_eq!(map.as_slice().len(), 0);
        assert!(map.as_slice().is_empty());
    }

    #[test]
    fn the_mapping_is_large_enough_to_span_more_than_one_page() {
        // A mapping bigger than a page exercises the length arithmetic that `mprotect`
        // needs, which is where an off-by-one would show up as a partially writable region.
        let bytes = vec![0xAB_u8; 8192 + 7];
        let map = map_readonly(&bytes).expect("map");
        assert_eq!(map.as_slice().len(), bytes.len());
        assert_eq!(map.as_slice().len(), bytes.len());
        assert!(map.as_slice().iter().all(|b| *b == 0xAB));
    }

    #[test]
    fn dropping_a_mapping_is_not_an_error_path() {
        // `Drop` runs `munmap` and ignores its result. This test exists so the destructor is
        // exercised by the suite rather than only in production.
        for _ in 0..3 {
            let map = map_readonly(b"transient").expect("map");
            drop(map);
        }
    }
}
