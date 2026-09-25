//! User-mode ↔ Kernel iletişimi
//!
//! `\\.\CrAcDriver` cihazına DeviceIoControl ile bağlanır. Her istek
//! HMAC-SHA256 ile imzalanır ve bir nonce içerir (replay koruması).
//! Karşılığı `driver/CrAcDriver.c` içindeki IOCTL handler'dır — IOCTL
//! kodları ve struct layout'ları iki tarafta BİREBİR aynı olmalı.

#![cfg(windows)]

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

type HmacSha256 = Hmac<Sha256>;

// CrAcDriver.h ile birebir aynı olmalı:
const IOCTL_PROTECT_PROCESS: u32 = ctl_code(0x8000, 0x800, 0, 0); // METHOD_BUFFERED, FILE_ANY_ACCESS
const IOCTL_QUERY_INTEGRITY: u32 = ctl_code(0x8000, 0x801, 0, 0);

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

#[repr(C)]
struct ProtectProcessRequest {
    pid: u32,
    nonce: [u8; 16],
    hmac: [u8; 32],
}

#[derive(Debug)]
pub enum DriverError {
    DeviceOpenFailed(windows::core::Error),
    IoctlFailed(windows::core::Error),
    AuthNotEstablished,
}

pub struct DriverComm {
    handle: HANDLE,
    /// IOCTL isteklerini imzalamak için driver ile paylaşılan anahtar.
    /// Bu anahtarın kendisi `SecureSession` benzeri bir el sıkışmayla
    /// (ör. driver'a gömülü bir public key + ECDH) kurulmalıdır; burada
    /// basitlik için doğrudan negotiate edilmiş bir simetrik anahtar
    /// varsayılır.
    hmac_key: [u8; 32],
}

impl DriverComm {
    /// `\\.\CrAcDriver` cihazını açar. Auth anahtarı ayrı bir güvenli
    /// kanaldan (ör. imzalı sürücü paketi içine gömülü + attestation)
    /// sağlanmalıdır; burada parametre olarak alınıyor.
    pub fn connect(hmac_key: [u8; 32]) -> Result<Self, DriverError> {
        let device_path: Vec<u16> = "\\\\.\\CrAcDriver\0".encode_utf16().collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(device_path.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            )
        }
        .map_err(DriverError::DeviceOpenFailed)?;

        Ok(Self { handle, hmac_key })
    }

    /// Belirtilen PID'yi driver'a "koru" olarak kaydettirir.
    /// (Kernel tarafında tipik olarak ObRegisterCallbacks ile
    /// PROCESS_TERMINATE / PROCESS_VM_WRITE gibi handle haklarını
    /// diğer process'lerden kısıtlamak şeklinde uygulanır.)
    pub fn protect_process(&self, pid: u32) -> Result<bool, DriverError> {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .expect("HMAC anahtar uzunluğu geçersiz");
        mac.update(&pid.to_le_bytes());
        mac.update(&nonce);
        let tag = mac.finalize().into_bytes();

        let mut hmac_bytes = [0u8; 32];
        hmac_bytes.copy_from_slice(&tag);

        let request = ProtectProcessRequest {
            pid,
            nonce,
            hmac: hmac_bytes,
        };

        let mut bytes_returned: u32 = 0;
        let mut response: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PROTECT_PROCESS,
                Some(&request as *const _ as *const c_void),
                std::mem::size_of::<ProtectProcessRequest>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                std::mem::size_of::<u32>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        ok.map_err(DriverError::IoctlFailed)?;
        Ok(response == 1)
    }

    /// Kernel self-integrity ihlali tespiti: driver kendi .text section
    /// hash'ini periyodik doğrular; bu fonksiyon sonucu sorgular.
    /// ⚠️ İhlal durumunda kernel panic (BugCheck) tetiklenmemeli —
    /// bu saldırganın DoS avantajı elde etmesini sağlar. Bunun yerine
    /// driver telemetry flag'i set eder, biz burada okuyup
    /// graceful degradation uygularız.
    pub fn check_driver_integrity(&self) -> Result<bool, DriverError> {
        let mut bytes_returned: u32 = 0;
        let mut integrity_ok: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_QUERY_INTEGRITY,
                None,
                0,
                Some(&mut integrity_ok as *mut _ as *mut c_void),
                std::mem::size_of::<u32>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        ok.map_err(DriverError::IoctlFailed)?;
        Ok(integrity_ok == 1)
    }
}

impl Drop for DriverComm {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
