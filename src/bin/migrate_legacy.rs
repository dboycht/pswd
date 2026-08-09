//! 旧数据迁移工具：把 pswd2.py 旧格式数据（dt_data.csv + ps_data.txt）
//! 导入新的 SQLite 密码库（pswd.db）。
//!
//! 用法：cargo run --bin migrate_legacy  （按向导逐步操作）

use std::fs;
use std::path::{Path, PathBuf};

use dialoguer::{Confirm, Input};
use pswd::{migrate, storage, ui};

const DEFAULT_DT: &str = "dt_data.csv";
const DEFAULT_PS: &str = "ps_data.txt";

fn main() {
    ui::setup_console();
    if let Err(e) = run() {
        println!("\n{e}");
    }
}

fn run() -> Result<(), String> {
    println!("=== 旧数据迁移工具 ===");
    println!("把 pswd2.py 旧格式数据（dt_data.csv + ps_data.txt）导入新的密码库（pswd.db）");
    println!("步骤：① 读取旧文件 ② 解码旧加密 ③ 用新方案重新加密 ④ 写入密码库 ⑤ 备份旧文件\n");
    if !Confirm::new()
        .with_prompt("开始迁移？")
        .default(true)
        .interact()
        .map_err(|_| "已取消".to_string())?
    {
        return Err("已取消迁移".into());
    }

    // ① 旧文件位置
    let dt_path = ask_path("旧数据文件 dt_data.csv 的路径（回车用默认）", DEFAULT_DT)?;
    let ps_path = ask_path("旧密码文件 ps_data.txt 的路径（回车用默认）", DEFAULT_PS)?;
    if !dt_path.exists() {
        return Err(format!("未找到旧数据文件：{}", dt_path.display()));
    }
    if !ps_path.exists() {
        return Err(format!("未找到旧密码文件：{}", ps_path.display()));
    }

    // ② 读取旧数据
    println!("\n正在读取旧文件…");
    let rows = migrate::read_legacy_dt(&dt_path)?;
    let ps_lines = migrate::read_legacy_ps(&ps_path)?;
    println!("CSV 记录 {} 条，密码文件 {} 行", rows.len(), ps_lines.len());
    if rows.len() != ps_lines.len() {
        println!("⚠ 警告：CSV 与密码文件行数不一致，将按较短者对齐，缺失项记为失败");
    }

    // ③ 打开/创建密码库
    let db = storage::DB_FILE;
    let vault = if Path::new(db).exists() {
        ui::unlock_flow(db)?
    } else {
        println!("\n密码库还不存在，先完成初始化：");
        let master = ui::setup_wizard(db)?;
        storage::open(db, &master).map_err(|e| e.to_string())?
    };

    // ④ 逐条迁移
    println!("\n正在迁移…");
    let result = migrate::import_legacy(&vault, &rows, &ps_lines);

    // ⑤ 汇总与备份
    println!("\n=== 迁移结果 ===");
    println!("成功导入：{} 条", result.ok);
    println!("失败：{} 条", result.failures.len());
    for (i, why) in &result.failures {
        println!("  第 {} 行：{why}", i + 1);
    }
    if result.ok > 0 && !result.failures.is_empty() {
        println!("提示：可修复失败项后再次运行本工具（已导入的记录会重复导入，请注意清理）");
    }
    if result.ok > 0
        && Confirm::new()
            .with_prompt("是否将旧文件备份为 .bak 后保留？")
            .default(true)
            .interact()
            .map_err(|_| "已取消".to_string())?
    {
        let dt_bak = PathBuf::from(format!("{}.bak", dt_path.to_string_lossy()));
        let ps_bak = PathBuf::from(format!("{}.bak", ps_path.to_string_lossy()));
        fs::rename(&dt_path, &dt_bak).map_err(|e| format!("备份 {} 失败：{e}", dt_path.display()))?;
        fs::rename(&ps_path, &ps_bak).map_err(|e| format!("备份 {} 失败：{e}", ps_path.display()))?;
        println!("旧文件已备份为：\n  {}\n  {}", dt_bak.display(), ps_bak.display());
    }
    println!("\n迁移完成！现在可用主程序 pswd 查看新库数据。");
    Ok(())
}

fn ask_path(prompt: &str, default: &str) -> Result<PathBuf, String> {
    let v: String = Input::new()
        .with_prompt(prompt)
        .default(default.to_string())
        .interact_text()
        .map_err(|_| "已取消".to_string())?;
    Ok(PathBuf::from(v.trim()))
}
