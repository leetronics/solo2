pub use embedded_hal::blocking::rng;
use littlefs2::fs::{Allocation, Filesystem};
use littlefs2::{const_ram_storage, consts};
use std::{fs::File, io::Write};
use trussed::store::DynFilesystem;

use trussed::platform;
use trussed::platform::{consent, reboot, ui};

pub use generic_array::{
    typenum::{U16, U512},
    GenericArray,
};

use generic_array::typenum::{U1022, U256};

const SOLO_STATE: &str = "solo-state.bin";

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
    pub type LOOKAHEAD_SIZE = U16;
    /// TODO: We can't actually be changed currently
    pub type FILENAME_MAX_PLUS_ONE = U256;
    pub type PATH_MAX_PLUS_ONE = U256;
    pub const FILEBYTES_MAX: usize = littlefs2::ll::LFS_FILE_MAX as _;
    /// TODO: We can't actually be changed currently
    pub type ATTRBYTES_MAX = U1022;
}

pub struct FileFlash {
    state: [u8; 128 * 1024],
}
impl FileFlash {
    pub fn new() -> Self {
        let mut state = [0u8; 128 * 1024];

        if let Ok(contents) = std::fs::read(SOLO_STATE) {
            println!("loaded {}", SOLO_STATE);
            state.copy_from_slice(contents.as_slice());
            Self { state }
        } else {
            println!("No state yet, creating");
            Self { state }
        }
    }
}

impl Default for FileFlash {
    fn default() -> Self {
        Self::new()
    }
}

impl littlefs2::driver::Storage for FileFlash {
    const READ_SIZE: usize = littlefs_params::READ_SIZE;
    const WRITE_SIZE: usize = littlefs_params::WRITE_SIZE;
    const BLOCK_SIZE: usize = littlefs_params::BLOCK_SIZE;

    const BLOCK_COUNT: usize = littlefs_params::BLOCK_COUNT;
    const BLOCK_CYCLES: isize = littlefs_params::BLOCK_CYCLES;

    type CACHE_SIZE = littlefs_params::CACHE_SIZE;
    type LOOKAHEAD_SIZE = littlefs_params::LOOKAHEAD_SIZE;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        buf.copy_from_slice(&self.state[off..off + buf.len()]);
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
        self.state[off..off + data.len()].copy_from_slice(data);
        let mut buffer = File::create(SOLO_STATE).unwrap();
        buffer.write_all(&self.state).unwrap();
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
        for byte in &mut self.state[off..off + len] {
            *byte = 0;
        }
        let mut buffer = File::create(SOLO_STATE).unwrap();
        buffer.write_all(&self.state).unwrap();
        Ok(len)
    }
}

// 8KB of RAM
const_ram_storage!(
    name = VolatileStorage,
    erase_value = 0x00,
    read_size = 1,
    write_size = 1,
    cache_size_ty = consts::U128,
    // this is a limitation of littlefs
    // https://git.io/JeHp9
    block_size = 128,
    block_count = 8192 / 128,
    lookahead_size_ty = consts::U8,
    filename_max_plus_one_ty = consts::U256,
    path_max_plus_one_ty = consts::U256,
);

// minimum: 2 blocks
// TODO: make this optional
const_ram_storage!(ExternalStorage, 1024);

#[derive(Clone, Copy)]
pub struct RunnerStore {
    ifs: &'static dyn DynFilesystem,
    efs: &'static dyn DynFilesystem,
    vfs: &'static dyn DynFilesystem,
}

impl trussed::store::Store for RunnerStore {
    fn ifs(&self) -> &dyn DynFilesystem {
        self.ifs
    }
    fn efs(&self) -> &dyn DynFilesystem {
        self.efs
    }
    fn vfs(&self) -> &dyn DynFilesystem {
        self.vfs
    }
}

pub type Store = RunnerStore;

#[derive(Default)]
pub struct UserInterface {}

impl trussed::platform::UserInterface for UserInterface {
    fn check_user_presence(&mut self) -> consent::Level {
        consent::Level::Normal
    }

    fn set_status(&mut self, status: ui::Status) {
        println!("Set status: {:?}", status);
    }

    fn refresh(&mut self) {}

    fn uptime(&mut self) -> core::time::Duration {
        core::time::Duration::from_millis(1000)
    }

    fn reboot(&mut self, to: reboot::To) -> ! {
        println!("Restart!  ({:?})", to);
        std::process::exit(25);
    }
}

platform!(Board,
    R: chacha20::ChaCha8Rng,
    S: Store,
    UI: UserInterface,
);

fn main() {
    // Allocate and mount three filesystems, leaking them to obtain 'static refs.
    let internal_storage: &'static mut FileFlash = Box::leak(Box::new(FileFlash::new()));
    let internal_alloc: &'static mut Allocation<FileFlash> =
        Box::leak(Box::new(Filesystem::allocate()));

    let external_storage: &'static mut ExternalStorage =
        Box::leak(Box::new(ExternalStorage::new()));
    let external_alloc: &'static mut Allocation<ExternalStorage> =
        Box::leak(Box::new(Filesystem::allocate()));

    let volatile_storage: &'static mut VolatileStorage =
        Box::leak(Box::new(VolatileStorage::new()));
    let volatile_alloc: &'static mut Allocation<VolatileStorage> =
        Box::leak(Box::new(Filesystem::allocate()));

    // Internal FS: try mount, format on failure.
    if Filesystem::mount(internal_alloc, internal_storage).is_err() {
        println!("Not yet formatted!  Formatting..");
        Filesystem::format(internal_storage).unwrap();
    }
    let internal_fs: &'static mut Filesystem<'static, FileFlash> = Box::leak(Box::new(
        Filesystem::mount(internal_alloc, internal_storage).unwrap(),
    ));

    // External FS (RAM): always needs format on first use.
    Filesystem::format(external_storage).unwrap();
    let external_fs: &'static mut Filesystem<'static, ExternalStorage> = Box::leak(Box::new(
        Filesystem::mount(external_alloc, external_storage).unwrap(),
    ));

    // Volatile FS (RAM): always needs format on first use.
    Filesystem::format(volatile_storage).unwrap();
    let volatile_fs: &'static mut Filesystem<'static, VolatileStorage> = Box::leak(Box::new(
        Filesystem::mount(volatile_alloc, volatile_storage).unwrap(),
    ));

    let store = RunnerStore {
        ifs: internal_fs,
        efs: external_fs,
        vfs: volatile_fs,
    };

    use trussed::service::SeedableRng;
    let rng = chacha20::ChaCha8Rng::from_seed([0u8; 32]);
    let pc_interface: UserInterface = Default::default();

    let board = Board::new(rng, store, pc_interface);
    let mut _trussed = trussed::service::Service::new(board);

    println!("hello trussed");
}
