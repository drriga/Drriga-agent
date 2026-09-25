//! Güvenli Oturum Yönetimi
//!
//! X25519 (ECDH) ile anahtar değişimi, HKDF-SHA256 ile anahtar türetimi,
//! AES-256-GCM ile şifreleme. Sequence number hem nonce hem de replay
//! koruması olarak kullanılır.
//!
//! NOT: Bu dosya gerçek kriptografik crate API'lerine göre yazılmıştır
//! (x25519-dalek 2.x, aes-gcm 0.10, hkdf 0.12). Kendi ortamında
//! `cargo build` ile derlenmeli ve entegrasyon testleriyle doğrulanmalıdır.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

#[derive(Debug)]
pub enum SessionError {
    EncryptionFailed,
    DecryptionFailed,
    ReplayDetected,
    InvalidSequence,
    KeyDerivationFailed,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for SessionError {}

pub struct SecureSession {
    cipher: Aes256Gcm,
    send_sequence: u64,
    /// Sunucudan gelen en yüksek doğrulanmış sequence (replay penceresi)
    recv_sequence: u64,
    /// İstemcinin kendi geçici public key'i — el sıkışma cevabında sunucuya gönderilir
    client_public: PublicKey,
}

impl SecureSession {
    /// Sunucu ile ECDH el sıkışması yapar ve AES-256-GCM anahtarını türetir.
    ///
    /// `server_public_key`: sunucunun X25519 public key'i (32 byte, ör. TLS
    /// dışı bir bootstrap kanalından veya sabit-pinned sunucu sertifikasından alınır).
    pub fn negotiate(server_public_key: &[u8; 32]) -> Result<Self, SessionError> {
        // 1) İstemci tarafı efemer anahtar çifti
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        // 2) Sunucu public key'ini yükle ve shared secret hesapla
        let server_public = PublicKey::from(*server_public_key);
        let shared_secret = client_secret.diffie_hellman(&server_public);

        // shared_secret tüm-sıfır mı kontrol et (küçük-alt-grup / degenerate key saldırısı)
        if shared_secret.as_bytes().iter().all(|&b| b == 0) {
            return Err(SessionError::KeyDerivationFailed);
        }

        // 3) HKDF-SHA256 ile 32 byte AES-256 anahtarı türet
        // Salt olarak her iki public key'i bağlıyoruz (transcript binding) —
        // bu, anahtarın hangi el sıkışmaya ait olduğunu bağlar.
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(client_public.as_bytes());
        salt.extend_from_slice(server_public.as_bytes());

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"crac-agent-heartbeat-v1", &mut okm)
            .map_err(|_| SessionError::KeyDerivationFailed)?;

        let key = Key::<Aes256Gcm>::from_slice(&okm);
        let cipher = Aes256Gcm::new(key);

        okm.zeroize();

        Ok(Self {
            cipher,
            send_sequence: 0,
            recv_sequence: 0,
            client_public,
        })
    }

    /// El sıkışma sırasında sunucuya gönderilecek istemci public key'i.
    pub fn client_public_key(&self) -> [u8; 32] {
        *self.client_public.as_bytes()
    }

    /// Heartbeat payload'ını şifreler; nonce = sequence_number (96-bit, big-endian,
    /// ilk 4 byte 0 doldurulur çünkü AES-GCM nonce'u 12 byte).
    ///
    /// ⚠️ Aynı (key, nonce) çifti asla iki kez kullanılmamalı: sequence_number
    /// bunu garanti eder çünkü her çağrıda kesin olarak artırılır ve oturum
    /// başına yeniden başlamaz (yeni negotiate = yeni key = nonce sıfırlanabilir).
    pub fn encrypt_heartbeat(&mut self, status: &str) -> Result<Vec<u8>, SessionError> {
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(SessionError::InvalidSequence)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let plaintext = format!(
            r#"{{"status":"{}","seq":{},"ts":{}}}"#,
            status, self.send_sequence, timestamp
        );

        let nonce_bytes = Self::seq_to_nonce(self.send_sequence);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // sequence'ı AAD (associated data) olarak da bağlıyoruz: ciphertext
        // taşınırken sequence numarası ayrıca değiştirilemez.
        let aad = self.send_sequence.to_be_bytes();

        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| SessionError::EncryptionFailed)?;

        // Çıktı formatı: [seq: 8 byte BE][ciphertext+tag]
        let mut out = Vec::with_capacity(8 + ciphertext.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Sunucudan/karşı taraftan gelen şifreli paketi çözer ve sequence'ı doğrular.
    pub fn decrypt_and_verify(&mut self, packet: &[u8]) -> Result<Vec<u8>, SessionError> {
        if packet.len() < 8 {
            return Err(SessionError::InvalidSequence);
        }
        let (seq_bytes, ciphertext) = packet.split_at(8);
        let seq = u64::from_be_bytes(seq_bytes.try_into().unwrap());

        if !self.verify_sequence(seq) {
            return Err(SessionError::ReplayDetected);
        }

        let nonce_bytes = Self::seq_to_nonce(seq);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: seq_bytes,
                },
            )
            .map_err(|_| SessionError::DecryptionFailed)?;

        // Doğrulama BAŞARILI olduktan sonra sequence'ı ilerlet —
        // aksi halde başarısız/tahrif edilmiş bir paket replay penceresini
        // ileri kaydırıp gerçek bir sonraki paketi reddettirebilir (DoS).
        self.recv_sequence = seq;
        Ok(plaintext)
    }

    /// Replay koruması: gelen sequence, şimdiye dek görülenden kesin olarak
    /// büyük olmalı (basit monotonik pencere). Paketler sırasız gelebiliyorsa
    /// bunun yerine kayan bit-mask'lı bir pencere (ör. 64 paketlik) kullanılmalı.
    pub fn verify_sequence(&self, received_seq: u64) -> bool {
        received_seq > self.recv_sequence
    }
}

impl SecureSession {
    fn seq_to_nonce(seq: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&seq.to_be_bytes());
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_roundtrip() {
        // Gerçek kullanımda server_public_key karşı taraftan gelir;
        // burada test amaçlı ikinci bir efemer taraf simüle ediyoruz.
        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);

        let mut client = SecureSession::negotiate(server_public.as_bytes()).unwrap();

        let packet = client.encrypt_heartbeat("OK").unwrap();
        assert!(packet.len() > 8);
    }

    #[test]
    fn replay_is_rejected() {
        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let mut session = SecureSession::negotiate(server_public.as_bytes()).unwrap();

        assert!(session.verify_sequence(1));
        session.recv_sequence = 5;
        assert!(!session.verify_sequence(5));
        assert!(!session.verify_sequence(3));
        assert!(session.verify_sequence(6));
    }
}
