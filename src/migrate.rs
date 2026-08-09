//! 旧数据迁移核心逻辑（与交互界面分离，便于测试）。
//! 旧格式：dt_data.csv（8 字段/行）+ ps_data.txt（每行一条旧 XOR 密文），按行号对齐。

use std::path::Path;

use crate::crypto;
use crate::storage::Vault;

/// 迁移结果汇总
pub struct ImportResult {
    pub ok: usize,
    pub failures: Vec<(usize, String)>,
}

/// 读取旧 CSV（无表头、容忍不完整行）
pub fn read_legacy_dt(path: &Path) -> Result<Vec<Vec<String>>, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_path(path)
        .map_err(|e| format!("读取 {} 失败：{e}", path.display()))?;
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| format!("CSV 解析失败：{e}"))?;
        rows.push(rec.iter().map(|s| s.to_string()).collect());
    }
    Ok(rows)
}

/// 读取旧密码文件（每行一条 Base64 密文，跳过空行）
pub fn read_legacy_ps(path: &Path) -> Result<Vec<String>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("读取 {} 失败：{e}", path.display()))?;
    Ok(content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// 逐条导入旧数据。rows 为 CSV 行，ps_lines 为密码文件行；
/// 两者按行号对齐（与旧版 _read_all 行为一致）。返回成功数 + 失败明细。
pub fn import_legacy(vault: &Vault, rows: &[Vec<String>], ps_lines: &[String]) -> ImportResult {
    let mut ok = 0usize;
    let mut failures: Vec<(usize, String)> = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        if row.len() < 8 {
            failures.push((i, format!("CSV 字段不足 8 个（实际 {} 个）", row.len())));
            continue;
        }
        let Some(enc) = ps_lines.get(i) else {
            failures.push((i, "密码文件缺少对应行".into()));
            continue;
        };
        let password = match crypto::legacy_xor_decode(enc) {
            Ok(p) => p,
            Err(e) => {
                failures.push((i, format!("旧密码解码失败：{e}")));
                continue;
            }
        };
        let record = crate::storage::RecordIn {
            app_name: row[0].trim().to_string(),
            nick_name: row[1].trim().to_string(),
            user_name: row[2].trim().to_string(),
            user_id: row[3].trim().to_string(),
            password,
            voucher: row[4].trim().to_string(),
            register: row[5].trim().to_string(),
            remark: row[6].trim().to_string(),
        };
        if let Err(e) = vault.add(&record) {
            failures.push((i, e));
            continue;
        }
        ok += 1;
    }
    ImportResult { ok, failures }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{self, RecoveryOpts};

    #[test]
    fn import_legacy_with_partial_failures() {
        // 建临时库
        let db_path = std::env::temp_dir().join(format!(
            "pswd_test_import_{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&db_path);
        let db = db_path.to_string_lossy().into_owned();
        storage::init(&db, "m", &RecoveryOpts { machine_binding: false, qa_pairs: vec![] }).unwrap();
        let vault = storage::open(&db, "m").unwrap();

        // 旧数据：2 条正常 + 1 条字段不足 + 1 条密码行缺失
        let rows = vec![
            vec![
                "微信".into(), "nick".into(), "user".into(), "id1".into(),
                "voucher".into(), "reg".into(), "note".into(), "2024-01-01".into(),
            ],
            vec![
                "google".into(), "".into(), "g@mail".into(), "".into(),
                "".into(), "".into(), "".into(), "2024-01-02".into(),
            ],
            vec!["字段不足".into(), "x".into(), "y".into(), "z".into()],
            vec![
                "badpwd".into(), "".into(), "".into(), "".into(),
                "".into(), "".into(), "".into(), "".into(),
            ],
        ];
        let ps_lines = vec![
            crypto::legacy_xor_encode("微信密码"),
            crypto::legacy_xor_encode("google-pw"),
            "!!invalid!!".to_string(), // 这条对应"字段不足"行，不会用到
        ];

        let result = import_legacy(&vault, &rows, &ps_lines);
        assert_eq!(result.ok, 2);
        assert_eq!(result.failures.len(), 2);
        // 第 3 行：字段不足；第 4 行：密码行缺失
        assert_eq!(result.failures[0].0, 2);
        assert_eq!(result.failures[1].0, 3);

        // 导入的数据可正确解密
        let records = vault.list().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| {
            r.app_name == "微信" && vault.decrypt(&r.password_blob).unwrap() == "微信密码"
        }));
        assert!(records.iter().any(|r| {
            r.app_name == "google" && vault.decrypt(&r.password_blob).unwrap() == "google-pw"
        }));
        drop(vault);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn legacy_file_io_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pswd_test_io_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dt = dir.join("dt_data.csv");
        let ps = dir.join("ps_data.txt");

        // 写入旧格式文件（UTF-8）
        std::fs::write(&dt, "微信,nick,user,id1,voucher,reg,note,2024-01-01\n\"含,逗号\",a,b,c,d,e,f,g\n").unwrap();
        let enc = crypto::legacy_xor_encode("密码");
        std::fs::write(&ps, format!("{enc}\n{enc}\n")).unwrap();

        let rows = read_legacy_dt(&dt).unwrap();
        let lines = read_legacy_ps(&ps).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][0], "含,逗号"); // CSV 引号解析正确
        assert_eq!(lines, vec![enc.clone(), enc]);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
