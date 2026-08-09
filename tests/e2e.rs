//! 端到端集成测试：通过公开 API 走完整用户流程
//! 初始化（主密码+机器码+密保问卷）→ 增删改查 → 错误凭据拒绝 → 恢复路径解锁。

use pswd::storage::{self, RecoveryOpts, RecordIn};

fn temp_db(name: &str) -> (std::path::PathBuf, String) {
    let path = std::env::temp_dir().join(format!("pswd_e2e_{}_{name}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let db = path.to_string_lossy().into_owned();
    (path, db)
}

#[test]
fn full_flow_with_all_recovery_paths() {
    let (path, db) = temp_db("full");

    // 初始化：主密码 + 机器码 + 两道密保问题
    let opts = RecoveryOpts {
        machine_binding: true,
        qa_pairs: vec![
            ("你的身份证号是什么？".into(), "110101199001011234".into()),
            ("你的手机号码是什么？".into(), "13800138000".into()),
        ],
    };
    storage::init(&db, "master-123", &opts).unwrap();

    // 恢复路径检测
    assert!(storage::machine_recovery_available(&db));
    assert_eq!(
        storage::qa_questions(&db),
        vec!["你的身份证号是什么？".to_string(), "你的手机号码是什么？".to_string()]
    );

    // 主密码解锁 → 写入数据
    let vault = storage::open(&db, "master-123").unwrap();
    let id = vault
        .add(&RecordIn {
            app_name: "微信".into(),
            nick_name: "自己".into(),
            user_name: "wx_user".into(),
            user_id: "wxid_001".into(),
            password: "Wx@2025".into(),
            voucher: "v1".into(),
            register: "r1".into(),
            remark: "工作用".into(),
        })
        .unwrap();
    drop(vault);

    // 错误主密码 → 拒绝
    assert!(matches!(
        storage::open(&db, "wrong").err(),
        Some(storage::UnlockError::WrongCredential)
    ));

    // 机器码恢复（真实读取本机 MachineGuid）
    let vault = storage::recover_with_machine(&db).unwrap();
    let rec = vault.get(id).unwrap().unwrap();
    assert_eq!(vault.decrypt(&rec.password_blob).unwrap(), "Wx@2025");
    // 恢复后重设主密码
    vault.reset_master("new-master").unwrap();
    drop(vault);
    assert!(storage::open(&db, "master-123").is_err());

    // 密保问卷恢复（第一题）
    let vault = storage::recover_with_qa(&db, 0, "110101199001011234").unwrap();
    assert!(vault.count().unwrap() == 1);
    drop(vault);
    // 错误答案 → 拒绝
    assert!(matches!(
        storage::recover_with_qa(&db, 1, "00000000000").err(),
        Some(storage::UnlockError::WrongCredential)
    ));

    // 新主密码解锁 → 修改/搜索/删除
    let vault = storage::open(&db, "new-master").unwrap();
    assert_eq!(vault.search("工作").unwrap().len(), 1);
    assert_eq!(vault.search("WX").unwrap().len(), 1); // 大小写不敏感
    vault.delete(id).unwrap();
    assert_eq!(vault.count().unwrap(), 0);
    drop(vault);

    let _ = std::fs::remove_file(&path);
}
