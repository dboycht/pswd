//! 存储层：SQLite 密码库（pswd.db）。
//!
//! 表 meta：存放各封包（盐 + 密文）与密保问题文本；
//! 表 records：记录数据，密码列为 AES-256-GCM 密文，非明文。

use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto::{self, VaultKey};

/// 数据库文件名（相对当前目录，与原版数据文件放一起）
pub const DB_FILE: &str = "pswd.db";

const META_MASTER_SALT: &str = "master_salt";
const META_MASTER_WRAPPED: &str = "master_wrapped";
const META_MACHINE_SALT: &str = "machine_salt";
const META_MACHINE_WRAPPED: &str = "machine_wrapped";
const META_DISPLAY_MODE: &str = "display_mode";

/// 主页显示模式：分页（默认）/ 一口气全部输出
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayMode {
    /// 分页：每页 PAGE_SIZE 条
    Paged,
    /// 全部：一口气输出所有记录名称
    Full,
}

impl DisplayMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisplayMode::Paged => "paged",
            DisplayMode::Full => "full",
        }
    }

    pub fn from_key(s: &str) -> DisplayMode {
        match s {
            "full" => DisplayMode::Full,
            _ => DisplayMode::Paged,
        }
    }
}

/// 恢复路径设置（初始化时传入）
pub struct RecoveryOpts {
    pub machine_binding: bool,
    /// (问题, 答案)
    pub qa_pairs: Vec<(String, String)>,
}

/// 解锁失败原因
#[derive(Debug)]
pub enum UnlockError {
    /// 凭据错误（主密码/机器码/密保答案不对，或数据损坏）
    WrongCredential,
    /// 该恢复路径未配置
    NotConfigured,
    Db(String),
}

impl std::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnlockError::WrongCredential => write!(f, "凭据错误或数据损坏"),
            UnlockError::NotConfigured => write!(f, "该恢复路径未配置"),
            UnlockError::Db(e) => write!(f, "数据库错误：{e}"),
        }
    }
}

/// 新增/保存记录时的输入
pub struct RecordIn {
    pub app_name: String,
    pub nick_name: String,
    pub user_name: String,
    pub user_id: String,
    pub password: String,
    pub voucher: String,
    pub register: String,
    pub remark: String,
}

/// 数据库中的一条记录（password 为密文，用 decrypt() 解开）
pub struct Record {
    pub id: i64,
    pub app_name: String,
    pub nick_name: String,
    pub user_name: String,
    pub user_id: String,
    pub voucher: String,
    pub register: String,
    pub remark: String,
    pub password_blob: String,
    pub stamp: String,
}

impl Record {
    pub fn fields(&self) -> [&str; 8] {
        [
            &self.app_name,
            &self.nick_name,
            &self.user_name,
            &self.user_id,
            &self.voucher,
            &self.register,
            &self.remark,
            &self.stamp,
        ]
    }
}

/// 已解锁的密码库
pub struct Vault {
    conn: Connection,
    vault_key: VaultKey,
}

fn now_stamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )
    .map_err(|e| format!("写入 meta 失败：{e}"))?;
    Ok(())
}

fn get_meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

/// 用当前目录下的 pswd.db 建立密码库（需先确认文件不存在）
pub fn init(db_path: &str, master_password: &str, recovery: &RecoveryOpts) -> Result<(), String> {
    if std::path::Path::new(db_path).exists() {
        return Err(format!("密码库 {db_path} 已存在，如需重建请先删除该文件"));
    }
    let conn = Connection::open(db_path).map_err(|e| format!("无法创建数据库：{e}"))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (
             key   TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS records (
             id        INTEGER PRIMARY KEY AUTOINCREMENT,
             app_name  TEXT NOT NULL,
             nick_name TEXT NOT NULL DEFAULT '',
             user_name TEXT NOT NULL DEFAULT '',
             user_id   TEXT NOT NULL DEFAULT '',
             voucher   TEXT NOT NULL DEFAULT '',
             register  TEXT NOT NULL DEFAULT '',
             remark    TEXT NOT NULL DEFAULT '',
             password  TEXT NOT NULL,
             stamp     TEXT NOT NULL
         );",
    )
    .map_err(|e| format!("建表失败：{e}"))?;

    let vault_key = VaultKey::generate();

    // 主密码封包
    let salt = crypto::generate_salt();
    let wrapped = crypto::wrap_key(master_password.as_bytes(), vault_key.as_bytes(), &salt)
        .map_err(|e| e.to_string())?;
    set_meta(&conn, META_MASTER_SALT, &crypto::encode_b64(&salt))?;
    set_meta(&conn, META_MASTER_WRAPPED, &wrapped)?;

    // 机器码封包
    if recovery.machine_binding {
        let code = crypto::machine_code().map_err(|e| e.to_string())?;
        let salt = crypto::generate_salt();
        let wrapped = crypto::wrap_key(code.as_bytes(), vault_key.as_bytes(), &salt)
            .map_err(|e| e.to_string())?;
        set_meta(&conn, META_MACHINE_SALT, &crypto::encode_b64(&salt))?;
        set_meta(&conn, META_MACHINE_WRAPPED, &wrapped)?;
    }

    // 密保问卷封包
    for (i, (question, answer)) in recovery.qa_pairs.iter().enumerate() {
        let salt = crypto::generate_salt();
        let wrapped = crypto::wrap_key(answer.as_bytes(), vault_key.as_bytes(), &salt)
            .map_err(|e| e.to_string())?;
        set_meta(&conn, &format!("qa_{i}_question"), question)?;
        set_meta(&conn, &format!("qa_{i}_salt"), &crypto::encode_b64(&salt))?;
        set_meta(&conn, &format!("qa_{i}_wrapped"), &wrapped)?;
    }
    Ok(())
}

/// 主密码解锁
pub fn open(db_path: &str, master_password: &str) -> Result<Vault, UnlockError> {
    let conn = Connection::open(db_path).map_err(|e| UnlockError::Db(e.to_string()))?;
    let wrapped = get_meta(&conn, META_MASTER_WRAPPED).ok_or(UnlockError::WrongCredential)?;
    let key = crypto::unwrap_key(master_password.as_bytes(), &wrapped)
        .map_err(|_| UnlockError::WrongCredential)?;
    Ok(Vault {
        conn,
        vault_key: VaultKey::from_bytes(key),
    })
}

/// 是否配置了机器码恢复路径
pub fn machine_recovery_available(db_path: &str) -> bool {
    Connection::open(db_path)
        .ok()
        .map(|conn| get_meta(&conn, META_MACHINE_WRAPPED).is_some())
        .unwrap_or(false)
}

/// 已配置的密保问题列表
pub fn qa_questions(db_path: &str) -> Vec<String> {
    let Ok(conn) = Connection::open(db_path) else {
        return vec![];
    };
    let mut out = vec![];
    for i in 0.. {
        match get_meta(&conn, &format!("qa_{i}_question")) {
            Some(q) => out.push(q),
            None => break,
        }
    }
    out
}

/// 机器码恢复：任何能接触本机的人均可使用此路径（恢复路径的固有代价）
pub fn recover_with_machine(db_path: &str) -> Result<Vault, UnlockError> {
    let conn = Connection::open(db_path).map_err(|e| UnlockError::Db(e.to_string()))?;
    let wrapped = get_meta(&conn, META_MACHINE_WRAPPED).ok_or(UnlockError::NotConfigured)?;
    let code = crypto::machine_code().map_err(|e| UnlockError::Db(e.to_string()))?;
    let key = crypto::unwrap_key(code.as_bytes(), &wrapped)
        .map_err(|_| UnlockError::WrongCredential)?;
    Ok(Vault {
        conn,
        vault_key: VaultKey::from_bytes(key),
    })
}

/// 密保问卷恢复：按问题序号与答案解锁
pub fn recover_with_qa(db_path: &str, index: usize, answer: &str) -> Result<Vault, UnlockError> {
    let conn = Connection::open(db_path).map_err(|e| UnlockError::Db(e.to_string()))?;
    let wrapped = get_meta(&conn, &format!("qa_{index}_wrapped"))
        .ok_or(UnlockError::NotConfigured)?;
    let key = crypto::unwrap_key(answer.as_bytes(), &wrapped)
        .map_err(|_| UnlockError::WrongCredential)?;
    Ok(Vault {
        conn,
        vault_key: VaultKey::from_bytes(key),
    })
}

impl Vault {
    /// 新增记录，返回新记录 id；密码在库内以密文保存
    pub fn add(&self, r: &RecordIn) -> Result<i64, String> {
        let blob = crypto::encrypt_password(&self.vault_key, &r.password).map_err(|e| e.to_string())?;
        let stamp = now_stamp();
        self.conn
            .execute(
                "INSERT INTO records (app_name, nick_name, user_name, user_id, voucher, register, remark, password, stamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    r.app_name.trim(),
                    r.nick_name.trim(),
                    r.user_name.trim(),
                    r.user_id.trim(),
                    r.voucher.trim(),
                    r.register.trim(),
                    r.remark.trim(),
                    blob,
                    stamp
                ],
            )
            .map_err(|e| format!("写入失败：{e}"))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// 保存对现有记录的修改（重新加密密码并更新时间戳）
    pub fn save(&self, id: i64, r: &RecordIn) -> Result<(), String> {
        let blob = crypto::encrypt_password(&self.vault_key, &r.password).map_err(|e| e.to_string())?;
        let stamp = now_stamp();
        let n = self
            .conn
            .execute(
                "UPDATE records SET app_name=?1, nick_name=?2, user_name=?3, user_id=?4,
                 voucher=?5, register=?6, remark=?7, password=?8, stamp=?9 WHERE id=?10",
                params![
                    r.app_name.trim(),
                    r.nick_name.trim(),
                    r.user_name.trim(),
                    r.user_id.trim(),
                    r.voucher.trim(),
                    r.register.trim(),
                    r.remark.trim(),
                    blob,
                    stamp,
                    id
                ],
            )
            .map_err(|e| format!("更新失败：{e}"))?;
        if n == 0 {
            return Err("记录不存在，可能已被删除".into());
        }
        Ok(())
    }

    /// 全部记录（按应用名排序：英文前、中文按拼音、其他最后）
    pub fn list(&self) -> Result<Vec<Record>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, app_name, nick_name, user_name, user_id, voucher, register, remark, password, stamp
                 FROM records",
            )
            .map_err(|e| format!("查询失败：{e}"))?;
        let mut records = stmt
            .query_map([], row_to_record)
            .map_err(|e| format!("查询失败：{e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("读取失败：{e}"))?;
        records.sort_by_key(|r: &Record| crate::sort::sort_key(&r.app_name));
        Ok(records)
    }

    /// 模糊搜索：关键词按顺序匹配（可跳跃）任意字段的 原文/整段拼音/拼音首字母
    pub fn search(&self, keyword: &str) -> Result<Vec<Record>, String> {
        let kw = keyword.trim();
        if kw.is_empty() {
            return self.list();
        }
        Ok(self
            .list()?
            .into_iter()
            .filter(|r| {
                [
                    &r.app_name,
                    &r.nick_name,
                    &r.user_name,
                    &r.user_id,
                    &r.voucher,
                    &r.register,
                    &r.remark,
                ]
                .iter()
                .any(|f| crate::sort::fuzzy_matches(f, kw))
            })
            .collect())
    }

    /// 按 id 取单条记录
    pub fn get(&self, id: i64) -> Result<Option<Record>, String> {
        self.conn
            .query_row(
                "SELECT id, app_name, nick_name, user_name, user_id, voucher, register, remark, password, stamp
                 FROM records WHERE id = ?1",
                params![id],
                row_to_record,
            )
            .optional()
            .map_err(|e| format!("查询失败：{e}"))
    }

    /// 删除记录
    pub fn delete(&self, id: i64) -> Result<(), String> {
        let n = self
            .conn
            .execute("DELETE FROM records WHERE id = ?1", params![id])
            .map_err(|e| format!("删除失败：{e}"))?;
        if n == 0 {
            return Err("记录不存在，可能已被删除".into());
        }
        Ok(())
    }

    /// 记录总数
    pub fn count(&self) -> Result<i64, String> {
        self.conn
            .query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))
            .map_err(|e| format!("查询失败：{e}"))
    }

    /// 解密记录密码；数据损坏时返回错误（由 UI 显示"无法解密"）
    pub fn decrypt(&self, blob: &str) -> Result<String, crypto::CryptoError> {
        crypto::decrypt_password(&self.vault_key, blob)
    }

    /// 重设主密码（重新封包金库密钥）
    pub fn reset_master(&self, new_password: &str) -> Result<(), String> {
        let salt = crypto::generate_salt();
        let wrapped = crypto::wrap_key(new_password.as_bytes(), self.vault_key.as_bytes(), &salt)
            .map_err(|e| e.to_string())?;
        set_meta(&self.conn, META_MASTER_SALT, &crypto::encode_b64(&salt))?;
        set_meta(&self.conn, META_MASTER_WRAPPED, &wrapped)?;
        Ok(())
    }

    /// 当前主页显示模式（默认分页，未设置时返回 Paged）
    pub fn display_mode(&self) -> DisplayMode {
        get_meta(&self.conn, META_DISPLAY_MODE)
            .map(|s| DisplayMode::from_key(&s))
            .unwrap_or(DisplayMode::Paged)
    }

    /// 设置主页显示模式
    pub fn set_display_mode(&self, mode: DisplayMode) -> Result<(), String> {
        set_meta(&self.conn, META_DISPLAY_MODE, mode.as_str())
    }
}

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<Record> {
    Ok(Record {
        id: row.get(0)?,
        app_name: row.get(1)?,
        nick_name: row.get(2)?,
        user_name: row.get(3)?,
        user_id: row.get(4)?,
        voucher: row.get(5)?,
        register: row.get(6)?,
        remark: row.get(7)?,
        password_blob: row.get(8)?,
        stamp: row.get(9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> String {
        let path = std::env::temp_dir().join(format!("pswd_test_{}_{name}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path.to_string_lossy().into_owned()
    }

    fn sample_record(app: &str) -> RecordIn {
        RecordIn {
            app_name: app.into(),
            nick_name: "nick".into(),
            user_name: "user".into(),
            user_id: "id1".into(),
            password: format!("pw-{app}"),
            voucher: "voucher".into(),
            register: "reg".into(),
            remark: "note".into(),
        }
    }

    #[test]
    fn init_open_wrong_password() {
        let db = temp_db("init");
        init(&db, "master", &RecoveryOpts { machine_binding: false, qa_pairs: vec![] }).unwrap();
        assert!(open(&db, "master").is_ok());
        assert!(matches!(open(&db, "wrong").err(), Some(UnlockError::WrongCredential)));
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn init_refuses_existing_db() {
        let db = temp_db("exists");
        init(&db, "m", &RecoveryOpts { machine_binding: false, qa_pairs: vec![] }).unwrap();
        assert!(init(&db, "m", &RecoveryOpts { machine_binding: false, qa_pairs: vec![] }).is_err());
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn qa_recovery_roundtrip() {
        let db = temp_db("qa");
        let opts = RecoveryOpts {
            machine_binding: false,
            qa_pairs: vec![("身份证号？".into(), "110101199001011234".into())],
        };
        init(&db, "master", &opts).unwrap();
        assert_eq!(qa_questions(&db), vec!["身份证号？".to_string()]);
        let v = recover_with_qa(&db, 0, "110101199001011234").unwrap();
        assert!(v.count().is_ok());
        assert!(matches!(
            recover_with_qa(&db, 0, "wrong-answer").err(),
            Some(UnlockError::WrongCredential)
        ));
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn add_list_get_update_delete() {
        let db = temp_db("crud");
        init(&db, "m", &RecoveryOpts { machine_binding: false, qa_pairs: vec![] }).unwrap();
        let v = open(&db, "m").unwrap();
        let id1 = v.add(&sample_record("微信")).unwrap();
        let id2 = v.add(&sample_record("wechat")).unwrap();
        assert_eq!(v.count().unwrap(), 2);

        // 排序：英文前，中文后
        let list = v.list().unwrap();
        assert_eq!(list[0].app_name, "wechat");
        assert_eq!(list[1].app_name, "微信");

        // 密文入库，非明文
        let rec = v.get(id1).unwrap().unwrap();
        assert!(!rec.password_blob.contains("pw-微信"));
        assert_eq!(v.decrypt(&rec.password_blob).unwrap(), "pw-微信");

        // 搜索（模糊：子序列 + 拼音）
        assert_eq!(v.search("微信").unwrap().len(), 1);
        assert_eq!(v.search("WECHAT").unwrap().len(), 1); // 大小写不敏感
        assert_eq!(v.search("wx").unwrap().len(), 1); // 拼音首字母匹配「微信」
        assert_eq!(v.search("不存在的").unwrap().len(), 0);
        assert_eq!(v.search("").unwrap().len(), 2); // 空关键词=全部

        // 修改
        let mut edit = sample_record("微信");
        edit.nick_name = "新昵称".into();
        edit.password = "新密码".into();
        v.save(id1, &edit).unwrap();
        let rec = v.get(id1).unwrap().unwrap();
        assert_eq!(rec.nick_name, "新昵称");
        assert_eq!(v.decrypt(&rec.password_blob).unwrap(), "新密码");

        // 删除
        v.delete(id1).unwrap();
        assert!(v.get(id1).unwrap().is_none());
        assert!(v.delete(id2).is_ok());
        assert_eq!(v.count().unwrap(), 0);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn reset_master_keeps_data() {
        let db = temp_db("reset");
        init(&db, "old", &RecoveryOpts { machine_binding: false, qa_pairs: vec![] }).unwrap();
        let v = open(&db, "old").unwrap();
        let id = v.add(&sample_record("微信")).unwrap();
        v.reset_master("new").unwrap();
        drop(v);
        assert!(open(&db, "old").is_err());
        let v = open(&db, "new").unwrap();
        let rec = v.get(id).unwrap().unwrap();
        assert_eq!(v.decrypt(&rec.password_blob).unwrap(), "pw-微信");
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn decrypt_corrupted_record_does_not_crash() {
        let db = temp_db("corrupt");
        init(&db, "m", &RecoveryOpts { machine_binding: false, qa_pairs: vec![] }).unwrap();
        let v = open(&db, "m").unwrap();
        let id = v.add(&sample_record("微信")).unwrap();
        // 手动写入垃圾密文
        v.conn
            .execute(
                "UPDATE records SET password='garbage' WHERE id=?1",
                params![id],
            )
            .unwrap();
        let rec = v.get(id).unwrap().unwrap();
        assert!(v.decrypt(&rec.password_blob).is_err());
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn display_mode_default_and_persist() {
        let db = temp_db("dmode");
        init(&db, "m", &RecoveryOpts { machine_binding: false, qa_pairs: vec![] }).unwrap();
        // 默认分页
        let v = open(&db, "m").unwrap();
        assert_eq!(v.display_mode(), DisplayMode::Paged);
        // 改为全部输出并持久化
        v.set_display_mode(DisplayMode::Full).unwrap();
        drop(v);
        let v = open(&db, "m").unwrap();
        assert_eq!(v.display_mode(), DisplayMode::Full);
        // 切回分页
        v.set_display_mode(DisplayMode::Paged).unwrap();
        drop(v);
        let v = open(&db, "m").unwrap();
        assert_eq!(v.display_mode(), DisplayMode::Paged);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn display_mode_unknown_value_falls_back() {
        let db = temp_db("dmode2");
        init(&db, "m", &RecoveryOpts { machine_binding: false, qa_pairs: vec![] }).unwrap();
        let v = open(&db, "m").unwrap();
        // 手动写入非法值 → 应回退到 Paged
        v.conn
            .execute(
                "INSERT INTO meta(key, value) VALUES('display_mode', 'bogus')
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [],
            )
            .unwrap();
        assert_eq!(v.display_mode(), DisplayMode::Paged);
        let _ = std::fs::remove_file(&db);
    }
}
