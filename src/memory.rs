use std::alloc::{alloc, dealloc, Layout};
use std::ptr::NonNull;
use zeroize::Zeroize;

pub struct SecureBuffer {
    ptr: NonNull<u8>,
    layout: Layout,
    exact_size: usize,
}

unsafe impl Send for SecureBuffer {}
unsafe impl Sync for SecureBuffer {}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        if size == 0 {
            let layout = Layout::from_size_align(1, 1).unwrap();
            return Self { ptr: NonNull::dangling(), layout, exact_size: 0 };
        }
        
        let ps = page_size();
        let alloc_size = (size + ps - 1) & !(ps - 1);
        let layout = Layout::from_size_align(alloc_size, ps).unwrap();
        
        let ptr = unsafe { NonNull::new(alloc(layout)).expect("Allocation failed") };
        
        if !lock_memory(ptr.as_ptr(), layout.size()) {
            panic!("FATAL: Failed to lock secure memory. Aborting to prevent secrets from paging to disk.");
        }
        
        Self { ptr, layout, exact_size: size }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut buf = Self::new(data.len());
        if !data.is_empty() {
            buf.as_mut_slice().copy_from_slice(data);
        }
        buf
    }

    pub fn as_slice(&self) -> &[u8] {
        if self.exact_size == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.exact_size) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.exact_size == 0 {
            return &mut [];
        }
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.exact_size) }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        if self.exact_size > 0 {
            unsafe {
                let full_slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size());
                full_slice.zeroize();
            }
            
            unlock_memory(self.ptr.as_ptr(), self.layout.size());
            unsafe {
                dealloc(self.ptr.as_ptr(), self.layout);
            }
        }
    }
}

#[cfg(windows)]
fn page_size() -> usize {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut info) };
    info.dwPageSize as usize
}

#[cfg(any(target_os = "linux", target_os = "ios"))]
fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(windows)]
fn lock_memory(ptr: *mut u8, size: usize) -> bool {
    use windows_sys::Win32::System::Memory::VirtualLock;
    unsafe { VirtualLock(ptr as _, size) != 0 }
}

#[cfg(windows)]
fn unlock_memory(ptr: *mut u8, size: usize) {
    use windows_sys::Win32::System::Memory::VirtualUnlock;
    unsafe { VirtualUnlock(ptr as _, size); }
}

#[cfg(any(target_os = "linux", target_os = "ios"))]
fn lock_memory(ptr: *mut u8, size: usize) -> bool {
    use libc::{mlock, madvise, MADV_DONTDUMP};
    unsafe { 
        if mlock(ptr as _, size) != 0 {
            return false;
        }
        madvise(ptr as _, size, MADV_DONTDUMP);
        true
    }
}

#[cfg(any(target_os = "linux", target_os = "ios"))]
fn unlock_memory(ptr: *mut u8, size: usize) {
    use libc::munlock;
    unsafe {
        munlock(ptr as _, size);
    }
}

pub fn set_process_protections() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
        let min_size = 64 * 1024 * 1024; // 64 MB
        let max_size = 128 * 1024 * 1024; // 128 MB
        unsafe {
            SetProcessWorkingSetSize(
                GetCurrentProcess(),
                min_size,
                max_size,
            );
        }
    }

    #[cfg(target_os = "linux")]
    {
        use libc::{prctl, PR_SET_DUMPABLE};
        unsafe {
            prctl(PR_SET_DUMPABLE, 0);
        }
    }
}
