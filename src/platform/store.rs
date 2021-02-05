#![allow(missing_docs)]
//! Trussed stores are built on underlying `littlefs` implementations.
//!
//! Here, we use a single binary file-backed littlefs implementation for
//! persistent storage, and RAM array-backed implementations for the volatile storage.
use std::{fs::File, io::{Seek as _, SeekFrom}};

pub use generic_array::{GenericArray, typenum::{consts, U16, U256, U512, U1022}};
use littlefs2::{const_ram_storage, fs::{Allocation, Filesystem}};
use log::info;
use trussed::types::{LfsResult, LfsStorage};

const_ram_storage!(VolatileStorage, 1024);
// currently, `trussed` needs a dummy parameter here
const_ram_storage!(ExternalStorage, 1024);

trussed::store!(Store,
    Internal: FileFlash,
    // External: FileFlash,
    // Volatile: FileFlash
    External: ExternalStorage,
    Volatile: VolatileStorage
);

pub fn init_store(state_path: impl AsRef<std::path::Path>) -> Store {
    let filesystem = FileFlash::new(state_path);
    // let external = FileFlash::new("/tmp/external.littlefs2");
    // let volatile = FileFlash::new("/tmp/volatile.littlefs2");

    static mut INTERNAL_STORAGE: Option<FileFlash> = None;
    unsafe { INTERNAL_STORAGE = Some(filesystem); }
    static mut INTERNAL_FS_ALLOC: Option<Allocation<FileFlash>> = None;
    unsafe { INTERNAL_FS_ALLOC = Some(Filesystem::allocate()); }

//     static mut EXTERNAL_STORAGE: Option<FileFlash> = None;
//     unsafe { EXTERNAL_STORAGE = Some(external); }
//     static mut EXTERNAL_FS_ALLOC: Option<Allocation<FileFlash>> = None;
//     unsafe { EXTERNAL_FS_ALLOC = Some(Filesystem::allocate()); }

//     static mut VOLATILE_STORAGE: Option<FileFlash> = None;
//     unsafe { VOLATILE_STORAGE = Some(volatile); }
//     static mut VOLATILE_FS_ALLOC: Option<Allocation<FileFlash>> = None;
//     unsafe { VOLATILE_FS_ALLOC = Some(Filesystem::allocate()); }

    static mut EXTERNAL_STORAGE: ExternalStorage = ExternalStorage::new();
    static mut EXTERNAL_FS_ALLOC: Option<Allocation<ExternalStorage>> = None;
    unsafe { EXTERNAL_FS_ALLOC = Some(Filesystem::allocate()); }

    static mut VOLATILE_STORAGE: VolatileStorage = VolatileStorage::new();
    static mut VOLATILE_FS_ALLOC: Option<Allocation<VolatileStorage>> = None;
    unsafe { VOLATILE_FS_ALLOC = Some(Filesystem::allocate()); }


    let store = Store::claim().unwrap();

    if store.mount(
        unsafe { INTERNAL_FS_ALLOC.as_mut().unwrap() },
        unsafe { INTERNAL_STORAGE.as_mut().unwrap() },
        // unsafe { EXTERNAL_FS_ALLOC.as_mut().unwrap() },
        // unsafe { EXTERNAL_STORAGE.as_mut().unwrap() },
        // unsafe { VOLATILE_FS_ALLOC.as_mut().unwrap() },
        // unsafe { VOLATILE_STORAGE.as_mut().unwrap() },
        unsafe { EXTERNAL_FS_ALLOC.as_mut().unwrap() },
        unsafe { &mut EXTERNAL_STORAGE },
        unsafe { VOLATILE_FS_ALLOC.as_mut().unwrap() },
        unsafe { &mut VOLATILE_STORAGE },
        // to trash existing data, set to true
        false,
    ).is_err() {
        store.mount(
            unsafe { INTERNAL_FS_ALLOC.as_mut().unwrap() },
            unsafe { INTERNAL_STORAGE.as_mut().unwrap() },
            // unsafe { EXTERNAL_FS_ALLOC.as_mut().unwrap() },
            // unsafe { EXTERNAL_STORAGE.as_mut().unwrap() },
            // unsafe { VOLATILE_FS_ALLOC.as_mut().unwrap() },
            // unsafe { VOLATILE_STORAGE.as_mut().unwrap() },
            unsafe { EXTERNAL_FS_ALLOC.as_mut().unwrap() },
            unsafe { &mut EXTERNAL_STORAGE },
            unsafe { VOLATILE_FS_ALLOC.as_mut().unwrap() },
            unsafe { &mut VOLATILE_STORAGE },
            // to trash existing data, set to true
            true,
        ).unwrap();
    };

    store
}

pub struct FileFlash {
    path: std::path::PathBuf,
}

impl FileFlash {
    const SIZE: u64 = 128*1024;

    pub fn new(state_path: impl AsRef<std::path::Path>) -> Self {

        let path: std::path::PathBuf = state_path.as_ref().into();

        if let Ok(file) = File::open(&path) {
            assert_eq!(file.metadata().unwrap().len(), Self::SIZE);
        } else {
            // TODO: error handling
            let file = File::create(&path).unwrap();
            file.set_len(Self::SIZE).unwrap();
            info!("Created new state file");
        }
        Self { path }
    }
}

#[allow(non_camel_case_types)]
pub mod littlefs_params {
    use super::*;
    pub const READ_SIZE: usize = 16;
    pub const WRITE_SIZE: usize = 512;
    pub const BLOCK_SIZE: usize = 512;

    pub const BLOCK_COUNT: usize = 256;
    // no wear-leveling for now
    pub const BLOCK_CYCLES: isize = -1;

    pub type CACHE_SIZE = U512;
    pub type LOOKAHEADWORDS_SIZE = U16;
    /// TODO: We can't actually be changed currently
    pub type FILENAME_MAX_PLUS_ONE = U256;
    pub type PATH_MAX_PLUS_ONE = U256;
    pub const FILEBYTES_MAX: usize = littlefs2::ll::LFS_FILE_MAX as _;
    /// TODO: We can't actually be changed currently
    pub type ATTRBYTES_MAX = U1022;
}

impl littlefs2::driver::Storage for FileFlash {
    const READ_SIZE: usize = littlefs_params::READ_SIZE;
    const WRITE_SIZE: usize = littlefs_params::WRITE_SIZE;
    const BLOCK_SIZE: usize = littlefs_params::BLOCK_SIZE;

    const BLOCK_COUNT: usize = littlefs_params::BLOCK_COUNT;
    const BLOCK_CYCLES: isize = littlefs_params::BLOCK_CYCLES;

    type CACHE_SIZE = littlefs_params::CACHE_SIZE;
    type LOOKAHEADWORDS_SIZE = littlefs_params::LOOKAHEADWORDS_SIZE;
    type FILENAME_MAX_PLUS_ONE = littlefs_params::FILENAME_MAX_PLUS_ONE;
    type PATH_MAX_PLUS_ONE = littlefs_params::PATH_MAX_PLUS_ONE;
    const FILEBYTES_MAX: usize = littlefs_params::FILEBYTES_MAX;
    type ATTRBYTES_MAX = littlefs_params::ATTRBYTES_MAX;


    fn read(&self, offset: usize, buffer: &mut [u8]) -> LfsResult<usize> {
        use std::io::Read;

        // debug!("reading {} bytes from {} in {:?}...", buffer.len(), offset, self.path);
        let mut file = File::open(&self.path).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let bytes_read = file.read(buffer).unwrap();
        assert_eq!(bytes_read, buffer.len());
        // debug!("..ok");
        Ok(bytes_read as _)
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> LfsResult<usize> {
        use std::io::Write;

        // debug!("writing {} bytes from {} in {:?}...", data.len(), offset, self.path);
        // debug!("{:?}", data);
        let mut file = std::fs::OpenOptions::new().write(true).open(&self.path).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let bytes_written = file.write(data).unwrap();
        assert_eq!(bytes_written, data.len());
        file.flush().unwrap();
        // debug!("..ok");
        Ok(bytes_written)
    }

    fn erase(&mut self, offset: usize, len: usize) -> LfsResult<usize> {
        use std::io::Write;

        // debug!("erasing {} bytes from {} in {:?}...", len, offset, self.path);
        let mut file = std::fs::OpenOptions::new().write(true).open(&self.path).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let zero_block = [0xFFu8; Self::BLOCK_SIZE];
        for _ in 0..(len/Self::BLOCK_SIZE) {
            let bytes_written = file.write(&zero_block).unwrap();
            assert_eq!(bytes_written, Self::BLOCK_SIZE);
        }
        file.flush().unwrap();
        // debug!("..ok");
        Ok(len)
    }

}

