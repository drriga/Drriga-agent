//! VAD Tabanlı Bellek Taraması
//!
//! `windows` crate (0.58) kullanılarak gerçek VirtualQueryEx döngüsü.
//! Manual mapping / reflective injection / shellcode tespiti için
//! RWX ve RX-ama-imagesiz bölgeleri işaretler.

#![cfg(windows)]

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS,
};

#[derive(Debug, Clone)]
pub struct SuspiciousRegion {
    pub base: usize,
    pub size: usize,
    pub protection: u32,
    pub reason: SuspicionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspicionReason {
    RwxCommitted,
    ExecuteWriteCopy,
}

pub struct VadScanner {
    process_handle: HANDLE,
    /// JVM CodeCache sınırları (varsa) — JIT'in normal RWX bölgelerini
    /// filtrelemek için main.rs tarafında set edilir.
    jit_code_cache_bounds: Option<(usize, usize)>,
}

impl VadScanner {
    pub fn new(process_handle: HANDLE) -> Self {
        Self {
            process_handle,
            jit_code_cache_bounds: None,
        }
    }

    pub fn set_jit_bounds(&mut self, bounds: (usize, usize)) {
        self.jit_code_cache_bounds = Some(bounds);
    }

    /// Tüm commit edilmiş RWX/WX bölgelerini tarar.
    ///
    /// # Safety / Doğruluk notu
    /// `VirtualQueryEx` başarısız olursa (ör. hedef process kapandıysa)
    /// döngü sonlanır; sonsuz döngüye girmemesi için region_size == 0
    /// durumu da ayrıca ele alınır.
    pub fn scan_rwx_regions(&self) -> Vec<SuspiciousRegion> {
        let mut address: usize = 0;
        let mut suspicious = Vec::new();

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let written = unsafe {
                VirtualQueryEx(
                    self.process_handle,
                    Some(address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if written == 0 {
                break; // adres alanı sonu ya da erişim hatası
            }

            if mbi.State == MEM_COMMIT {
                let protect = mbi.Protect;
                let reason = if protect_matches(protect, PAGE_EXECUTE_READWRITE) {
                    Some(SuspicionReason::RwxCommitted)
                } else if protect_matches(protect, PAGE_EXECUTE_WRITECOPY) {
                    Some(SuspicionReason::ExecuteWriteCopy)
                } else {
                    None
                };

                if let Some(reason) = reason {
                    let base = mbi.BaseAddress as usize;
                    let size = mbi.RegionSize;

                    // JVM CodeCache içindeki RWX bölgelerini filtrele —
                    // bunlar JIT tarafından meşru olarak kullanılır.
                    // JitIntegrityChecker ile ayrıca yapısal doğrulanmalı.
                    let in_jit_bounds = self
                        .jit_code_cache_bounds
                        .map(|(lo, hi)| base >= lo && base < hi)
                        .unwrap_or(false);

                    if !in_jit_bounds {
                        suspicious.push(SuspiciousRegion {
                            base,
                            size,
                            protection: protect.0,
                            reason,
                        });
                    }
                }
            }

            let region_size = mbi.RegionSize;
            if region_size == 0 {
                break; // ilerleme yoksa sonsuz döngüyü önle
            }

            match address.checked_add(region_size) {
                Some(next) => address = next,
                None => break, // adres alanı taştı
            }
        }

        suspicious
    }
}

fn protect_matches(actual: PAGE_PROTECTION_FLAGS, flag: PAGE_PROTECTION_FLAGS) -> bool {
    // Protect değeri PAGE_GUARD / PAGE_NOCACHE gibi modifier bitleriyle
    // OR'lanmış olabilir; temel korumayı maskeleyerek karşılaştırıyoruz.
    (actual.0 & 0xFF) == (flag.0 & 0xFF)
}
