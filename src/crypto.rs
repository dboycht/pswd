//! 加密层：Argon2id 密钥派生 + AES-256-GCM 加密 + KEK 封包 + 旧版 XOR 兼容解码。
//!
//! 设计：随机金库密钥（vault key）负责加密所有记录密码；
//! 金库密钥用多把 KEK（主密码 / 机器码 / 密保答案各自 Argon2id 派生）分别封包存放，
//! 任一路径可解开，形成"主密码 + 恢复路径"机制。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
/// 旧版（pswd2.py）的 XOR 密钥，仅用于迁移旧数据
pub const LEGACY_XOR_KEY: &[u8] = b"FuckUDouBao";

/// Argon2id 参数（OWASP 基线：19 MiB 内存、2 轮、1 并行度）
const ARGON2_M_COST: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

#[derive(Debug)]
pub enum CryptoError {
    Argon2(argon2::Error),
    Base64(base64::DecodeError),
    Aead,
    MachineId(String),
    BadFormat(String),
    /// 解密失败 = 凭据错误或数据损坏
    WrongSecret,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Argon2(e) => write!(f, "密钥派生失败：{e}"),
            CryptoError::Base64(e) => write!(f, "Base64 解码失败：{e}"),
            CryptoError::Aead => write!(f, "加解密失败"),
            CryptoError::MachineId(e) => write!(f, "无法读取机器码：{e}"),
            CryptoError::BadFormat(m) => write!(f, "密文格式错误：{m}"),
            CryptoError::WrongSecret => write!(f, "凭据错误或数据损坏"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// 金库密钥：随机 32 字节，Drop 时内存清零
pub struct VaultKey([u8; KEY_LEN]);

impl VaultKey {
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        SysRng
            .try_fill_bytes(&mut k)
            .expect("无法获取系统随机数（系统熵源不可用）");
        Self(k)
    }

    pub fn from_bytes(k: [u8; KEY_LEN]) -> Self {
        Self(k)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 生成随机盐
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    SysRng
        .try_fill_bytes(&mut s)
        .expect("无法获取系统随机数（系统熵源不可用）");
    s
}

/// Base64 编码（存储用）
pub fn encode_b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Base64 解码
pub fn decode_b64(s: &str) -> Result<Vec<u8>, CryptoError> {
    B64.decode(s).map_err(CryptoError::Base64)
}

/// Argon2id 从口令派生 KEK
pub fn derive_kek(secret: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(CryptoError::Argon2)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; KEY_LEN];
    argon2
        .hash_password_into(secret, salt, &mut kek)
        .map_err(CryptoError::Argon2)?;
    Ok(kek)
}

/// AES-256-GCM 加密，返回 (随机 nonce, 密文)
fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce_bytes)
        .expect("无法获取系统随机数（系统熵源不可用）");
    let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| CryptoError::Aead)?;
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::Aead)?;
    Ok((nonce_bytes.to_vec(), ct))
}

/// AES-256-GCM 解密；认证失败返回 WrongSecret
fn open(key: &[u8; KEY_LEN], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadFormat("nonce 长度错误".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| CryptoError::Aead)?;
    cipher
        .decrypt(&nonce, ct)
        .map_err(|_| CryptoError::WrongSecret)
}

/// 用口令（secret）封包金库密钥，返回 "盐.随机数.密文"（均 Base64）
pub fn wrap_key(secret: &[u8], vault_key: &[u8; KEY_LEN], salt: &[u8]) -> Result<String, CryptoError> {
    let kek = derive_kek(secret, salt)?;
    let (nonce, ct) = seal(&kek, vault_key)?;
    Ok(format!(
        "{}.{}.{}",
        encode_b64(salt),
        encode_b64(&nonce),
        encode_b64(&ct)
    ))
}

/// 用口令解开封包的金库密钥；凭据错误返回 WrongSecret
pub fn unwrap_key(secret: &[u8], wrapped: &str) -> Result<[u8; KEY_LEN], CryptoError> {
    let parts: Vec<&str> = wrapped.split('.').collect();
    if parts.len() != 3 {
        return Err(CryptoError::BadFormat("封包应含三段".into()));
    }
    let salt = decode_b64(parts[0])?;
    let nonce = decode_b64(parts[1])?;
    let ct = decode_b64(parts[2])?;
    let kek = derive_kek(secret, &salt)?;
    let opened = open(&kek, &nonce, &ct)?;
    if opened.len() != KEY_LEN {
        return Err(CryptoError::BadFormat("密钥长度错误".into()));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&opened);
    Ok(key)
}

/// 加密单条记录密码，返回 "随机数.密文"（均 Base64）
pub fn encrypt_password(key: &VaultKey, plaintext: &str) -> Result<String, CryptoError> {
    let (nonce, ct) = seal(key.as_bytes(), plaintext.as_bytes())?;
    Ok(format!("{}.{}", encode_b64(&nonce), encode_b64(&ct)))
}

/// 解密单条记录密码；凭据错误或数据损坏返回 WrongSecret
pub fn decrypt_password(key: &VaultKey, blob: &str) -> Result<String, CryptoError> {
    let parts: Vec<&str> = blob.split('.').collect();
    if parts.len() != 2 {
        return Err(CryptoError::BadFormat("密文应含两段".into()));
    }
    let nonce = decode_b64(parts[0])?;
    let ct = decode_b64(parts[1])?;
    let opened = open(key.as_bytes(), &nonce, &ct)?;
    String::from_utf8(opened).map_err(|_| CryptoError::BadFormat("解密结果非 UTF-8".into()))
}

/// 读取本机机器码（Windows 为注册表 MachineGuid）
pub fn machine_code() -> Result<String, CryptoError> {
    machine_uid::get().map_err(|e| CryptoError::MachineId(e.to_string()))
}

/// ---- 旧版（pswd2.py）XOR 加密/解密，仅迁移用 ----
/// 旧版加密：XOR + Base64（与 pswd2.py 的 coder() 完全一致）
pub fn legacy_xor_encode(s: &str) -> String {
    let data = s.as_bytes();
    let encrypted: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ LEGACY_XOR_KEY[i % LEGACY_XOR_KEY.len()])
        .collect();
    encode_b64(&encrypted)
}

/// 旧版解密：Base64 + XOR（与 pswd2.py 的 decoder() 完全一致）
pub fn legacy_xor_decode(s: &str) -> Result<String, CryptoError> {
    let data = decode_b64(s)?;
    let decrypted: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ LEGACY_XOR_KEY[i % LEGACY_XOR_KEY.len()])
        .collect();
    String::from_utf8(decrypted).map_err(|_| CryptoError::BadFormat("解码结果非 UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let vault_key = VaultKey::generate();
        let salt = generate_salt();
        let wrapped = wrap_key(b"master-password", vault_key.as_bytes(), &salt).unwrap();
        let key = unwrap_key(b"master-password", &wrapped).unwrap();
        assert_eq!(key, *vault_key.as_bytes());
    }

    #[test]
    fn unwrap_with_wrong_secret_fails() {
        let vault_key = VaultKey::generate();
        let salt = generate_salt();
        let wrapped = wrap_key(b"right-password", vault_key.as_bytes(), &salt).unwrap();
        let err = unwrap_key(b"wrong-password", &wrapped).unwrap_err();
        assert!(matches!(err, CryptoError::WrongSecret));
    }

    #[test]
    fn password_encrypt_decrypt_roundtrip() {
        let key = VaultKey::generate();
        let blob = encrypt_password(&key, "P@ssw0rd 中文!").unwrap();
        assert!(!blob.contains("P@ssw0rd"), "密文不应包含明文");
        assert_eq!(decrypt_password(&key, &blob).unwrap(), "P@ssw0rd 中文!");
    }

    #[test]
    fn password_decrypt_with_wrong_key_fails() {
        let k1 = VaultKey::generate();
        let k2 = VaultKey::generate();
        let blob = encrypt_password(&k1, "secret").unwrap();
        assert!(matches!(
            decrypt_password(&k2, &blob).unwrap_err(),
            CryptoError::WrongSecret
        ));
    }

    #[test]
    fn decrypt_corrupted_blob_fails_gracefully() {
        let key = VaultKey::generate();
        // 格式错误
        assert!(matches!(
            decrypt_password(&key, "not-a-valid-blob").unwrap_err(),
            CryptoError::BadFormat(_)
        ));
        // Base64 错误
        assert!(matches!(
            decrypt_password(&key, "!!!.!!!").unwrap_err(),
            CryptoError::Base64(_)
        ));
    }

    /// 与 pswd2.py 的 coder() 输出交叉验证（样本由 Python 3.12 运行原版算法生成）
    #[test]
    fn legacy_xor_matches_original_python() {
        // python: coder("123456") == "d0dQX2By"
        assert_eq!(legacy_xor_encode("123456"), "d0dQX2By");
        assert_eq!(legacy_xor_decode("d0dQX2By").unwrap(), "123456");
        // python: coder("我的密码MyP@ss!") == "oP3yjM/AitrEhs/HOBo7FTccVA=="
        assert_eq!(legacy_xor_encode("我的密码MyP@ss!"), "oP3yjM/AitrEhs/HOBo7FTccVA==");
        assert_eq!(legacy_xor_decode("oP3yjM/AitrEhs/HOBo7FTccVA==").unwrap(), "我的密码MyP@ss!");
    }

    #[test]
    fn legacy_xor_unicode_roundtrip() {
        let s = "我的密码MyP@ss!";
        let enc = legacy_xor_encode(s);
        assert_eq!(legacy_xor_decode(&enc).unwrap(), s);
        // 损坏数据不崩溃
        assert!(legacy_xor_decode("!!!!").is_err());
    }

    #[test]
    fn derive_kek_deterministic_and_distinct() {
        let salt = [7u8; SALT_LEN];
        let k1 = derive_kek(b"same", &salt).unwrap();
        let k2 = derive_kek(b"same", &salt).unwrap();
        let k3 = derive_kek(b"same", &[8u8; SALT_LEN]).unwrap();
        let k4 = derive_kek(b"other", &salt).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);
    }
}
