include!(concat!(env!("OUT_DIR"), "/build_constants.rs"));

use crate::hal;
use hal::drivers::timer;
use hal::peripherals::ctimer;
use littlefs2::{const_ram_storage, consts};
use trussed::platform;
use trussed::store::DynFilesystem;
use trussed::pipe::{ServiceEndpoint, TrussedChannel};
use trussed::types::CoreContext;
use trussed::backend::BackendId;
use trussed::serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl};
use trussed_fs_info::FsInfoExtension;
use trussed_hkdf::HkdfExtension;
use trussed_manage::ManageExtension;
use trussed_staging::{StagingBackend, StagingContext};

// Compile time assertion that build_constants::CONFIG_FILESYSTEM_BOUNDARY is 512 byte aligned.
const _FILESYSTEM_ALIGNED_CHECK: usize = ((core::mem::size_of::<
    [u8; build_constants::CONFIG_FILESYSTEM_BOUNDARY % 512],
>() == 0) as usize)
    - 1;
// Compile time check that the flashregion does NOT spill over the 631.5KB boundary.
const _FILESYSTEM_WITHIN_FLASH_CHECK: usize = ((core::mem::size_of::<
    [u8; ((build_constants::CONFIG_FILESYSTEM_BOUNDARY) <= (631 * 1024 + 512)) as usize],
>() == 1) as usize)
    - 1;

pub mod littlefs_params {
    use crate::hal;
    pub const READ_SIZE: usize = 16;
    pub const WRITE_SIZE: usize = 512;
    pub const BLOCK_SIZE: usize = 512;

    // no wear-leveling for now
    pub const BLOCK_CYCLES: isize = -1;

    #[allow(non_camel_case_types, reason = "These are type-level constants")]
    pub type CACHE_SIZE = hal::drivers::flash::U512;
    #[allow(non_camel_case_types, reason = "These are type-level constants")]
    pub type LOOKAHEAD_SIZE = hal::drivers::flash::U16;
}

#[cfg(feature = "no-encrypted-storage")]
mod littlefs2_filesystem {
    use super::*;

    pub struct PlainFilesystem {
        flash_gordon: hal::drivers::flash::FlashGordon,
    }

    impl PlainFilesystem {
        const BASE_OFFSET: usize = build_constants::CONFIG_FILESYSTEM_BOUNDARY;

        pub fn new(flash_gordon: hal::drivers::flash::FlashGordon) -> Self {
            Self { flash_gordon }
        }
    }

    impl littlefs2::driver::Storage for PlainFilesystem {
        const READ_SIZE: usize = super::littlefs_params::READ_SIZE;
        const WRITE_SIZE: usize = super::littlefs_params::WRITE_SIZE;
        const BLOCK_SIZE: usize = super::littlefs_params::BLOCK_SIZE;

        const BLOCK_COUNT: usize =
            ((631 * 1024 + 512) - build_constants::CONFIG_FILESYSTEM_BOUNDARY) / 512;
        const BLOCK_CYCLES: isize = super::littlefs_params::BLOCK_CYCLES;

        type CACHE_SIZE = super::littlefs_params::CACHE_SIZE;
        type LOOKAHEAD_SIZE = super::littlefs_params::LOOKAHEAD_SIZE;

        fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
            <hal::drivers::flash::FlashGordon as hal::traits::flash::Read<
                hal::drivers::flash::U16,
            >>::read(&self.flash_gordon, Self::BASE_OFFSET + off, buf);
            Ok(buf.len())
        }

        fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
            let ret = <hal::drivers::flash::FlashGordon as hal::traits::flash::WriteErase<
                hal::drivers::flash::U512,
                hal::drivers::flash::U512,
            >>::write(&mut self.flash_gordon, Self::BASE_OFFSET + off, data);
            ret.map(|_| data.len())
                .map_err(|_| littlefs2::io::Error::IO)
        }

        fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
            let first_page = (Self::BASE_OFFSET + off) / 512;
            let pages = len / 512;
            for i in 0..pages {
                <hal::drivers::flash::FlashGordon as hal::traits::flash::WriteErase<
                    hal::drivers::flash::U512,
                    hal::drivers::flash::U512,
                >>::erase_page(&mut self.flash_gordon, first_page + i)
                .map_err(|_| littlefs2::io::Error::IO)?;
            }
            Ok(512 * len)
        }
    }
}

#[cfg(not(feature = "no-encrypted-storage"))]
mod littlefs2_prince_filesystem {
    use super::*;

    pub struct PrinceFilesystem {
        flash_gordon: hal::drivers::flash::FlashGordon,
        prince: hal::peripherals::prince::Prince<hal::typestates::init_state::Enabled>,
    }

    impl PrinceFilesystem {
        const BASE_OFFSET: usize = build_constants::CONFIG_FILESYSTEM_BOUNDARY;

        pub fn new(
            flash_gordon: hal::drivers::flash::FlashGordon,
            prince: hal::peripherals::prince::Prince<hal::typestates::init_state::Enabled>,
        ) -> Self {
            Self {
                flash_gordon,
                prince,
            }
        }
    }

    impl littlefs2::driver::Storage for PrinceFilesystem {
        const READ_SIZE: usize = super::littlefs_params::READ_SIZE;
        const WRITE_SIZE: usize = super::littlefs_params::WRITE_SIZE;
        const BLOCK_SIZE: usize = super::littlefs_params::BLOCK_SIZE;

        const BLOCK_COUNT: usize =
            ((631 * 1024 + 512) - build_constants::CONFIG_FILESYSTEM_BOUNDARY) / 512;
        const BLOCK_CYCLES: isize = super::littlefs_params::BLOCK_CYCLES;

        type CACHE_SIZE = super::littlefs_params::CACHE_SIZE;
        type LOOKAHEAD_SIZE = super::littlefs_params::LOOKAHEAD_SIZE;

        fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
            self.prince.enable_region_2_for(|| {
                let flash: *const u8 = (Self::BASE_OFFSET + off) as *const u8;
                for i in 0..buf.len() {
                    buf[i] = unsafe { *flash.offset(i as isize) };
                }
            });
            Ok(buf.len())
        }

        fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
            let prince = &mut self.prince;
            let flash_gordon = &mut self.flash_gordon;
            let ret = prince.write_encrypted(|prince| {
                prince.enable_region_2_for(|| {
                    <hal::drivers::flash::FlashGordon as hal::traits::flash::WriteErase<
                        hal::drivers::flash::U512,
                        hal::drivers::flash::U512,
                    >>::write(flash_gordon, Self::BASE_OFFSET + off, data)
                })
            });
            ret.map(|_| data.len())
                .map_err(|_| littlefs2::io::Error::IO)
        }

        fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
            let first_page = (Self::BASE_OFFSET + off) / 512;
            let pages = len / 512;
            for i in 0..pages {
                <hal::drivers::flash::FlashGordon as hal::traits::flash::WriteErase<
                    hal::drivers::flash::U512,
                    hal::drivers::flash::U512,
                >>::erase_page(&mut self.flash_gordon, first_page + i)
                .map_err(|_| littlefs2::io::Error::IO)?;
            }
            Ok(512 * len)
        }
    }
}

#[cfg(feature = "no-encrypted-storage")]
pub use littlefs2_filesystem::PlainFilesystem;
#[cfg(feature = "no-encrypted-storage")]
pub type FlashStorage = PlainFilesystem;
#[cfg(not(feature = "no-encrypted-storage"))]
pub use littlefs2_prince_filesystem::PrinceFilesystem;
#[cfg(not(feature = "no-encrypted-storage"))]
pub type FlashStorage = PrinceFilesystem;

pub mod usb;
pub use usb::{CcidClass, CtapHidClass, EnabledUsbPeripheral, SerialClass, UsbClasses};

// 8KB of RAM
const_ram_storage!(
    name=VolatileStorage,
    erase_value=0xff,
    read_size=1,
    write_size=1,
    cache_size_ty=consts::U128,
    // this is a limitation of littlefs
    // https://git.io/JeHp9
    block_size=128,
    // block_size=128,
    block_count=8192/104,
    lookahead_size_ty=consts::U8,
    filename_max_plus_one_ty=consts::U256,
    path_max_plus_one_ty=consts::U256,
);

// minimum: 2 blocks
// TODO: make this optional
const_ram_storage!(ExternalStorage, 1024);

/// Store implementation using three mounted littlefs2 filesystems.
#[derive(Clone, Copy)]
pub struct RunnerStore {
    ifs: &'static dyn DynFilesystem,
    efs: &'static dyn DynFilesystem,
    vfs: &'static dyn DynFilesystem,
}

impl RunnerStore {
    pub fn new(
        ifs: &'static dyn DynFilesystem,
        efs: &'static dyn DynFilesystem,
        vfs: &'static dyn DynFilesystem,
    ) -> Self {
        Self { ifs, efs, vfs }
    }
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

pub type ThreeButtons = board::ThreeButtons;
pub type RgbLed = board::RgbLed;

platform!(Board,
    R: hal::peripherals::rng::Rng<hal::Enabled>,
    S: Store,
    UI: board::trussed::UserInterface<ThreeButtons, RgbLed>,
);

/// Extension dispatch type providing FsInfo, Hkdf, and Manage backends via trussed-staging.
/// Required because fido-authenticator 0.2 unconditionally needs FsInfoClient + HkdfClient,
/// and admin-app requires ManageClient.
#[derive(Default)]
pub struct Dispatch {
    backend: StagingBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendIds {
    StagingBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionIds {
    FsInfo = 0,
    Hkdf = 1,
    Manage = 2,
}

impl From<ExtensionIds> for u8 {
    fn from(id: ExtensionIds) -> u8 {
        id as u8
    }
}

impl TryFrom<u8> for ExtensionIds {
    type Error = trussed::Error;
    fn try_from(id: u8) -> Result<Self, trussed::Error> {
        match id {
            0 => Ok(Self::FsInfo),
            1 => Ok(Self::Hkdf),
            2 => Ok(Self::Manage),
            _ => Err(trussed::Error::FunctionNotSupported),
        }
    }
}

impl ExtensionId<FsInfoExtension> for Dispatch {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::FsInfo;
}

impl ExtensionId<HkdfExtension> for Dispatch {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::Hkdf;
}

impl ExtensionId<ManageExtension> for Dispatch {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::Manage;
}

impl ExtensionDispatch for Dispatch {
    type BackendId = BackendIds;
    type Context = StagingContext;
    type ExtensionId = ExtensionIds;

    fn core_request<P: trussed::platform::Platform>(
        &mut self,
        backend: &Self::BackendId,
        ctx: &mut trussed::types::Context<Self::Context>,
        request: &trussed::api::Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, trussed::Error> {
        use trussed::backend::Backend;
        match backend {
            BackendIds::StagingBackend => {
                self.backend.request(&mut ctx.core, &mut ctx.backends, request, resources)
            }
        }
    }

    fn extension_request<P: trussed::platform::Platform>(
        &mut self,
        _backend: &Self::BackendId,
        extension: &Self::ExtensionId,
        ctx: &mut trussed::types::Context<Self::Context>,
        request: &trussed::api::request::SerdeExtension,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::api::reply::SerdeExtension, trussed::Error> {
        match extension {
            ExtensionIds::FsInfo => ExtensionImpl::<FsInfoExtension>::extension_request_serialized(
                &mut self.backend, &mut ctx.core, &mut ctx.backends, request, resources,
            ),
            ExtensionIds::Hkdf => ExtensionImpl::<HkdfExtension>::extension_request_serialized(
                &mut self.backend, &mut ctx.core, &mut ctx.backends, request, resources,
            ),
            ExtensionIds::Manage => ExtensionImpl::<ManageExtension>::extension_request_serialized(
                &mut self.backend, &mut ctx.core, &mut ctx.backends, request, resources,
            ),
        }
    }
}

#[derive(Default)]
pub struct Syscall {}

impl trussed::client::Syscall for Syscall {
    #[inline]
    fn syscall(&mut self) {
        rtic::pend(board::hal::raw::Interrupt::OS_EVENT);
    }
}

/// Service endpoint type for our Dispatch (staging backends: FsInfo, Hkdf, Manage).
pub type TrussedEndpoint = ServiceEndpoint<'static, BackendIds, StagingContext>;
/// Client type for apps — parameterized with Dispatch to get extension support.
pub type TrussedClient = trussed::ClientImplementation<'static, Syscall, Dispatch>;

/// Backends exposed to each trussed client (all apps get staging backend access).
static STAGING_BACKENDS: [BackendId<BackendIds>; 1] =
    [BackendId::Custom(BackendIds::StagingBackend)];

/// Wrapper around the trussed Service that also holds the service endpoints.
/// `process()` and `update_ui()` are called from the RTIC OS_EVENT handler and
/// the periodic UI task respectively.
pub struct Trussed {
    service: trussed::Service<Board, Dispatch>,
    endpoints: heapless::Vec<TrussedEndpoint, 8>,
}

impl Trussed {
    pub fn new(service: trussed::Service<Board, Dispatch>) -> Self {
        Self {
            service,
            endpoints: heapless::Vec::new(),
        }
    }

    pub fn add_endpoint(&mut self, ep: TrussedEndpoint) {
        self.endpoints.push(ep).ok();
    }

    pub fn process(&mut self) {
        self.service.process(&mut self.endpoints);
    }

    pub fn update_ui(&mut self) {
        self.service.update_ui();
    }
}

pub type Iso14443 = nfc_device::Iso14443<'static, board::nfc::NfcChip>;

pub type ExternalInterrupt = hal::Pint<hal::typestates::init_state::Enabled>;

pub type ApduDispatch = apdu_dispatch::dispatch::ApduDispatch<'static>;
pub type CtaphidDispatch =
    ctaphid_dispatch::Dispatch<'static, 'static, { ctaphid_dispatch::DEFAULT_MESSAGE_SIZE }>;

/// Minimal status implementation for admin-app.
#[cfg(feature = "admin-app")]
pub struct AdminStatus {
    random_error: bool,
}

#[cfg(feature = "admin-app")]
impl Default for AdminStatus {
    fn default() -> Self {
        Self { random_error: false }
    }
}

#[cfg(feature = "admin-app")]
impl admin_app::StatusBytes for AdminStatus {
    type Serialized = [u8; 1];

    fn set_random_error(&mut self, value: bool) {
        self.random_error = value;
    }

    fn get_random_error(&self) -> bool {
        self.random_error
    }

    fn serialize(&self) -> Self::Serialized {
        [self.random_error as u8]
    }
}

#[cfg(feature = "admin-app")]
pub type AdminApp = admin_app::App<TrussedClient, board::Reboot, AdminStatus>;
#[cfg(feature = "piv-authenticator")]
pub type PivApp = piv_authenticator::Authenticator<TrussedClient, { apdu_dispatch::command::SIZE }>;
#[cfg(feature = "oath-authenticator")]
pub type OathApp = oath_authenticator::Authenticator<TrussedClient>;
#[cfg(feature = "fido-authenticator")]
pub type FidoApp = fido_authenticator::Authenticator<fido_authenticator::Conforming, TrussedClient>;
#[cfg(feature = "fido-authenticator")]
pub type FidoConfig = fido_authenticator::Config;
#[cfg(feature = "ndef-app")]
pub type NdefApp = ndef_app::App<'static>;
#[cfg(feature = "provisioner-app")]
pub type ProvisionerApp = provisioner_app::Provisioner<Store, FlashStorage, TrussedClient>;

use apdu_dispatch::response::SIZE as ResponseSize;
use apdu_dispatch::App as ApduApp;
use ctaphid_dispatch::app::App as CtaphidApp;

pub type DynamicClockController = board::clock_controller::DynamicClockController;
pub type NfcWaitExtender = timer::Timer<ctimer::Ctimer0<hal::typestates::init_state::Enabled>>;
pub type PerformanceTimer = timer::Timer<ctimer::Ctimer4<hal::typestates::init_state::Enabled>>;

// Static trussed channels — one per app. Channels are split during Apps::new().
#[cfg(feature = "admin-app")]
static ADMIN_TRUSSED_CHANNEL: TrussedChannel = TrussedChannel::new();
#[cfg(feature = "fido-authenticator")]
static FIDO_TRUSSED_CHANNEL: TrussedChannel = TrussedChannel::new();
#[cfg(feature = "oath-authenticator")]
static OATH_TRUSSED_CHANNEL: TrussedChannel = TrussedChannel::new();
#[cfg(feature = "piv-authenticator")]
static PIV_TRUSSED_CHANNEL: TrussedChannel = TrussedChannel::new();
#[cfg(feature = "provisioner-app")]
static PROVISIONER_TRUSSED_CHANNEL: TrussedChannel = TrussedChannel::new();

/// Helper: split a static channel, register the service endpoint with `trussed`,
/// and return the client end.
fn make_client(
    channel: &'static TrussedChannel,
    client_id: &'static littlefs2::path::Path,
    trussed: &mut Trussed,
) -> TrussedClient {
    let (req, resp) = channel.split().expect("channel already split");
    let ep = ServiceEndpoint::new(
        resp,
        CoreContext::new(littlefs2::path::PathBuf::from(client_id)),
        &STAGING_BACKENDS,
    );
    trussed.add_endpoint(ep);
    TrussedClient::new(req, Syscall::default(), None)
}

pub struct ProvisionerNonPortable {
    pub store: Store,
    pub stolen_filesystem: &'static mut FlashStorage,
    pub nfc_powered: bool,
}

pub struct Apps {
    #[cfg(feature = "admin-app")]
    pub admin: AdminApp,
    #[cfg(feature = "fido-authenticator")]
    pub fido: FidoApp,
    #[cfg(feature = "oath-authenticator")]
    pub oath: OathApp,
    #[cfg(feature = "ndef-app")]
    pub ndef: NdefApp,
    #[cfg(feature = "piv-authenticator")]
    pub piv: PivApp,
    #[cfg(feature = "provisioner-app")]
    pub provisioner: ProvisionerApp,
}

impl Apps {
    pub fn new(
        trussed: &mut Trussed,
        #[cfg(feature = "provisioner-app")] provisioner_np: ProvisionerNonPortable,
    ) -> Self {
        #[cfg(feature = "admin-app")]
        let admin = {
            let client = make_client(&ADMIN_TRUSSED_CHANNEL, littlefs2::path!("admin"), trussed);
            AdminApp::with_default_config(
                client,
                hal::uuid(),
                build_constants::CARGO_PKG_VERSION,
                env!("CARGO_PKG_VERSION"),
                AdminStatus::default(),
                &[],
            )
        };

        #[cfg(feature = "fido-authenticator")]
        let fido = {
            let client = make_client(&FIDO_TRUSSED_CHANNEL, littlefs2::path!("fido"), trussed);
            fido_authenticator::Authenticator::new(
                client,
                fido_authenticator::Conforming {},
                FidoConfig {
                    max_msg_size: ctaphid_dispatch::DEFAULT_MESSAGE_SIZE,
                    skip_up_timeout: None,
                    max_resident_credential_count: Some(50),
                    large_blobs: None,
                    nfc_transport: false,
                },
            )
        };

        #[cfg(feature = "oath-authenticator")]
        let oath = {
            let client = make_client(&OATH_TRUSSED_CHANNEL, littlefs2::path!("oath"), trussed);
            OathApp::new(client)
        };

        #[cfg(feature = "piv-authenticator")]
        let piv = {
            let client = make_client(&PIV_TRUSSED_CHANNEL, littlefs2::path!("piv"), trussed);
            PivApp::new(client)
        };

        #[cfg(feature = "ndef-app")]
        let ndef = NdefApp::new();

        #[cfg(feature = "provisioner-app")]
        let provisioner = {
            let client = make_client(
                &PROVISIONER_TRUSSED_CHANNEL,
                littlefs2::path!("attn"),
                trussed,
            );
            let ProvisionerNonPortable {
                store,
                stolen_filesystem,
                nfc_powered,
            } = provisioner_np;
            ProvisionerApp::new(client, store, stolen_filesystem, nfc_powered)
        };

        Self {
            #[cfg(feature = "admin-app")]
            admin,
            #[cfg(feature = "fido-authenticator")]
            fido,
            #[cfg(feature = "oath-authenticator")]
            oath,
            #[cfg(feature = "ndef-app")]
            ndef,
            #[cfg(feature = "piv-authenticator")]
            piv,
            #[cfg(feature = "provisioner-app")]
            provisioner,
        }
    }

    #[inline(never)]
    pub fn apdu_dispatch<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut [&mut dyn ApduApp<ResponseSize>]) -> T,
    {
        f(&mut [
            #[cfg(feature = "ndef-app")]
            &mut self.ndef,
            #[cfg(feature = "piv-authenticator")]
            &mut self.piv,
            #[cfg(feature = "oath-authenticator")]
            &mut self.oath,
            #[cfg(feature = "fido-authenticator")]
            &mut self.fido,
            #[cfg(feature = "admin-app")]
            &mut self.admin,
            #[cfg(feature = "provisioner-app")]
            &mut self.provisioner,
        ])
    }

    #[inline(never)]
    pub fn ctaphid_dispatch<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut [&mut dyn CtaphidApp<'static, { ctaphid_dispatch::DEFAULT_MESSAGE_SIZE }>]) -> T,
    {
        f(&mut [
            #[cfg(feature = "fido-authenticator")]
            &mut self.fido,
            #[cfg(feature = "admin-app")]
            &mut self.admin,
        ])
    }
}
