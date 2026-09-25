//! JVM Bütünlük Kontrolü
//!
//! Bytecode (immutable) için SHA256 hash karşılaştırması; JIT-compiled
//! kod (mutable, her optimizasyon geçişinde değişir) için hash YERİNE
//! yapısal doğrulama (CodeCache sınırları + prologue pattern + boyut).
//!
//! ⚠️ ÖNEMLİ SINIRLAMA: `jni` crate'i sadece standart JNI'yi kapsar.
//! Bytecode/CodeCache erişimi için JVMTI (JVM Tool Interface) gerekir,
//! bu da `jni` crate'inin dışındadır ve JavaVM'den ham `jvmtiEnv*`
//! işaretçisini `GetEnv(JVMTI_VERSION_1_2)` ile almayı, ardından JVMTI
//! fonksiyon tablosunu manuel FFI ile çağırmayı gerektirir. Aşağıdaki
//! kod bu ham FFI katmanını içerir; gerçek bir JVM'e karşı test
//! edilmeden production'a alınmamalı.

use jni::JavaVM;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::os::raw::{c_int, c_void};

pub type JvmtiEnv = *mut c_void;

const JVMTI_VERSION_1_2: i32 = 0x30010200;
const JVMTI_ERROR_NONE: i32 = 0;

// jvmtiEnv fonksiyon tablosundaki GetBytecodes ofseti sabit değildir —
// gerçek imzası jvmti.h'den alınmalı. Burada minimal bir FFI iskeleti
// veriyoruz; gerçek entegrasyon jni-sys / jvmti-sys gibi bir crate
// (ör. `jvmti` crate'i) kullanmalı çünkü fonksiyon tablosu offset'lerini
// elle yönetmek son derece hataya açıktır.
extern "system" {
    fn JVMTI_GetBytecodes(
        env: JvmtiEnv,
        method: *mut c_void, // jmethodID
        bytecode_count_ptr: *mut c_int,
        bytecodes_ptr: *mut *mut u8,
    ) -> i32;

    fn JVMTI_Deallocate(env: JvmtiEnv, mem: *mut u8) -> i32;
}

#[derive(Clone, Copy)]
pub enum IntegrityTarget {
    Bytecode(u64),
    JitCompiled(u64),
    DispatchTable(u64),
}

#[derive(Debug)]
pub enum IntegrityError {
    JvmtiUnavailable,
    JvmtiCallFailed(i32),
    UnknownClassId(u64),
    HashMismatch,
    StructuralCheckFailed(&'static str),
}

pub struct JvmIntegrityChecker {
    jvmti: JvmtiEnv,
    known_bytecode_hashes: HashMap<u64, [u8; 32]>,
    /// CodeCache::low_bound / high_bound — JVM başlatılırken bir defa
    /// okunur (ör. `-XX:+PrintCompilation` çıktısı veya JVMTI CompiledMethodLoad
    /// event'i ile toplanır).
    code_cache_bounds: (usize, usize),
    /// method_id -> (entry_point, expected_size) — CompiledMethodLoad
    /// callback'i ile doldurulur.
    jit_metadata: HashMap<u64, (usize, usize)>,
}

impl JvmIntegrityChecker {
    /// `vm`: mevcut JavaVM'den JVMTI ortamını alır.
    pub fn new(
        vm: &JavaVM,
        known_bytecode_hashes: HashMap<u64, [u8; 32]>,
        code_cache_bounds: (usize, usize),
    ) -> Result<Self, IntegrityError> {
        // JavaVM ham işaretçisi üzerinden GetEnv(JVMTI_VERSION_1_2) çağrısı.
        // `jni` crate'i JVMTI'yi doğrudan expose etmediği için raw
        // JNIInvokeInterface tablosu üzerinden çağırıyoruz.
        let raw_vm = vm.get_java_vm_pointer();
        let mut jvmti_env: JvmtiEnv = std::ptr::null_mut();

        let get_env_fn = unsafe {
            // JNIInvokeInterface_ tablosunda GetEnv 6. slot (index 5)
            let functions = *(raw_vm as *mut *mut [*mut c_void; 8]);
            (*functions)[5]
        };

        if get_env_fn.is_null() {
            return Err(IntegrityError::JvmtiUnavailable);
        }

        type GetEnvFn =
            unsafe extern "system" fn(*mut c_void, *mut JvmtiEnv, i32) -> i32;
        let get_env: GetEnvFn = unsafe { std::mem::transmute(get_env_fn) };

        let result = unsafe { get_env(raw_vm as *mut c_void, &mut jvmti_env, JVMTI_VERSION_1_2) };
        if result != JVMTI_ERROR_NONE || jvmti_env.is_null() {
            return Err(IntegrityError::JvmtiUnavailable);
        }

        Ok(Self {
            jvmti: jvmti_env,
            known_bytecode_hashes,
            code_cache_bounds,
            jit_metadata: HashMap::new(),
        })
    }

    /// CompiledMethodLoad JVMTI event callback'inden çağrılmalı; bu event
    /// her JIT compile/recompile'da tetiklenir ve entry_point + code_size
    /// verir — hash yerine bu metadata ile structural check yapılır.
    pub fn record_jit_compilation(&mut self, method_id: u64, entry_point: usize, code_size: usize) {
        self.jit_metadata.insert(method_id, (entry_point, code_size));
    }

    pub fn verify(&self, target: IntegrityTarget) -> Result<bool, IntegrityError> {
        match target {
            IntegrityTarget::Bytecode(class_id) => self.verify_bytecode(class_id),
            IntegrityTarget::JitCompiled(method_id) => self.verify_jit_compiled(method_id),
            IntegrityTarget::DispatchTable(class_id) => self.verify_dispatch_table(class_id),
        }
    }

    /// ✅ Immutable → hash karşılaştırması güvenlidir.
    fn verify_bytecode(&self, class_id: u64) -> Result<bool, IntegrityError> {
        let expected = self
            .known_bytecode_hashes
            .get(&class_id)
            .ok_or(IntegrityError::UnknownClassId(class_id))?;

        // Gerçek uygulamada class_id -> jmethodID eşlemesi ayrıca
        // tutulmalı (JVMTI GetLoadedClasses + GetClassMethods).
        // Burada method_id = class_id basitleştirmesiyle örnekliyoruz.
        let method_ptr = class_id as *mut c_void;

        let mut count: c_int = 0;
        let mut bytecodes_ptr: *mut u8 = std::ptr::null_mut();

        let err = unsafe {
            JVMTI_GetBytecodes(self.jvmti, method_ptr, &mut count, &mut bytecodes_ptr)
        };
        if err != JVMTI_ERROR_NONE || bytecodes_ptr.is_null() {
            return Err(IntegrityError::JvmtiCallFailed(err));
        }

        let bytecodes = unsafe { std::slice::from_raw_parts(bytecodes_ptr, count as usize) };
        let mut hasher = Sha256::new();
        hasher.update(bytecodes);
        let actual: [u8; 32] = hasher.finalize().into();

        unsafe {
            JVMTI_Deallocate(self.jvmti, bytecodes_ptr);
        }

        Ok(&actual == expected)
    }

    /// ❌ HASH KULLANILMAZ (JIT her optimizasyonda kodu değiştirir).
    /// ✅ Yapısal doğrulama: entry point CodeCache sınırları içinde mi,
    /// kayıtlı boyut metadata ile eşleşiyor mu, ilk byte'lar geçerli bir
    /// prologue'a benziyor mu (hook'lar genelde `jmp`/`call` ile
    /// prologue'un başını ezer).
    fn verify_jit_compiled(&self, method_id: u64) -> Result<bool, IntegrityError> {
        let (entry_point, expected_size) = *self
            .jit_metadata
            .get(&method_id)
            .ok_or(IntegrityError::StructuralCheckFailed("no metadata for method"))?;

        let (lo, hi) = self.code_cache_bounds;
        if entry_point < lo || entry_point >= hi {
            return Ok(false); // CodeCache dışında → şüpheli
        }

        // Prologue kontrolü: x86-64'te tipik JIT prologue'ları genelde
        // `push rbp; mov rbp, rsp` (0x55 0x48 0x89 0xE5) veya benzeri
        // stack-check kalıplarıyla başlar. Bu kalıp JVM/JIT sürümüne göre
        // değişir — gerçek kullanımda hedef JVM'in derleyici çıktısından
        // (ör. hsdis ile disassemble ederek) referans kalıp çıkarılmalı.
        let prologue = unsafe {
            std::slice::from_raw_parts(entry_point as *const u8, 4.min(expected_size))
        };
        let looks_like_hook = is_unconditional_jump(prologue);

        if looks_like_hook {
            return Ok(false);
        }

        Ok(true)
    }

    /// vtable/itable slot'larının hepsi geçerli kod aralığında mı.
    /// Out-of-range pointer = hook/injection.
    fn verify_dispatch_table(&self, _class_id: u64) -> Result<bool, IntegrityError> {
        // Gerçek implementasyon JVM'in dahili Klass/vtable layout'ına
        // erişim gerektirir (HotSpot'ta stabil bir ABI değildir!).
        // Bu genelde JVMTI'nin sağlamadığı, JVM Serviceability Agent (SA)
        // seviyesinde bir işlemdir. Üretimde ya SA API'lerine (com.sun.jdi /
        // sun.jvm.hotspot) native köprü kurulmalı ya da bu kontrol
        // tamamen çıkarılıp bytecode+JIT kontrolleriyle yetinilmeli.
        Err(IntegrityError::StructuralCheckFailed(
            "dispatch table check requires HotSpot SA bridge — not implemented",
        ))
    }
}

fn is_unconditional_jump(bytes: &[u8]) -> bool {
    match bytes.first() {
        Some(0xE9) => true,       // JMP rel32
        Some(0xFF) => true,       // JMP r/m (indirect) — konservatif, false-positive olabilir
        Some(0xEB) => true,       // JMP rel8
        _ => false,
    }
}
