//! 密码管理器主程序：解锁 → 搜索/查看/新增/修改/删除。

use std::io::Write;
use std::path::Path;

use dialoguer::{Confirm, Input, Select};
use pswd::{storage, ui};
use storage::{Record, RecordIn, Vault};

/// 字段顺序（与旧版数据栏一致；密码是第 5 个字段）
const FIELD_NAMES: [&str; 8] = [
    "应用名称", "昵称", "用户名", "ID", "密码", "凭证应用", "注册凭证", "备注",
];

/// 每页显示的记录数
const PAGE_SIZE: usize = 15;

fn main() {
    ui::setup_console();
    if let Err(e) = run() {
        println!("\n{e}");
    }
}

fn run() -> Result<(), String> {
    let db = storage::DB_FILE;
    let vault = if !Path::new(db).exists() {
        // 首次使用：初始化向导，直接用刚设置的主密码解锁
        let master = ui::setup_wizard(db)?;
        storage::open(db, &master).map_err(|e| e.to_string())?
    } else {
        ui::unlock_flow(db)?
    };
    // 进入主界面前清屏：吞没解锁/初始化页面的旧输出（主密码输入行、解锁成功等）
    clear_screen()?;
    main_loop(&vault)
}

/// 主界面指令行的提示文字
const MAIN_PROMPT: &str = "↑↓选择 / [回车]打开 / 输入搜索词 / [A]新增 / [C]修改 / [D]删除 / [S]设置 / [Q]退出";

/// 主循环：高亮选择式列表（↑/↓ 移动高亮、回车打开、输入过滤、A/C/D/Q 命令）
/// 进入详情/向导子界面前后清屏，实现「切新页面」效果（旧输出文字被吞没）。
fn main_loop(vault: &Vault) -> Result<(), String> {
    // 终端按键读取器（非终端环境为 None，退化为普通读行）
    let reader = ui::KeyReader::new().ok();
    let mut filter: Option<String> = None;
    // 当前高亮记录的全局索引（跨页连续，0 起）
    let mut sel: usize = 0;
    // 搜索/命令输入缓冲
    let mut buf = String::new();
    // 上次渲染占用行数（0 = 尚未渲染或需要重新定位，直接往下画）
    let mut last_rows: usize = 0;
    loop {
        let records = match &filter {
            None => vault.list()?,
            Some(kw) => vault.search(kw)?,
        };
        // 约束高亮索引在合法范围
        if records.is_empty() {
            sel = 0;
        } else if sel >= records.len() {
            sel = records.len() - 1;
        }
        // 显示模式：分页（PAGE_SIZE）/ 全部（一口气输出所有名称）
        let display_mode = vault.display_mode();
        let page_size = match display_mode {
            storage::DisplayMode::Paged => PAGE_SIZE,
            storage::DisplayMode::Full => records.len().max(1),
        };

        // 渲染列表（终端环境用缓冲重绘，非终端退化为普通打印）
        if reader.is_some() {
            render_select_list(&records, sel, &filter, page_size, &mut last_rows)?;
        } else {
            render_plain_list(&records, &filter, page_size)?;
        }

        // 指令输入：↑/↓ 移动高亮（返回 None 表示重新渲染列表）
        let input = match &reader {
            Some(r) => match read_command(r, records.len(), &mut sel, &mut buf)? {
                Some(s) => s,
                None => continue,
            },
            None => read_line_fallback()?,
        };

        if input.is_empty() {
            // 回车（无输入）→ 打开当前高亮记录
            if records.is_empty() {
                println!("{}", ui::theme::dim("（没有记录可打开）"));
            } else {
                clear_screen()?; // 切页：清掉旧列表
                open_record(vault, &records[sel], sel + 1)?;
                clear_screen()?; // 返回：清掉详情页，回到干净列表
            }
            last_rows = 0;
            buf.clear();
            continue;
        }
        match input.to_ascii_lowercase().as_str() {
            "a" | "w" => {
                clear_screen()?;
                add_wizard(vault)?;
                clear_screen()?;
                filter = None;
                sel = 0;
                last_rows = 0;
            }
            "c" => {
                if records.is_empty() {
                    println!("{}", ui::theme::dim("没有记录可修改"));
                } else {
                    clear_screen()?;
                    change_one(vault, records[sel].id, sel + 1)?;
                    clear_screen()?;
                }
                last_rows = 0;
            }
            "d" => {
                if records.is_empty() {
                    println!("{}", ui::theme::dim("没有记录可删除"));
                } else {
                    clear_screen()?;
                    confirm_delete(vault, &records[sel], sel + 1)?;
                    clear_screen()?;
                    filter = None;
                    sel = 0;
                }
                last_rows = 0;
            }
            "s" => {
                clear_screen()?;
                settings_menu(vault)?;
                clear_screen()?;
                sel = 0;
                last_rows = 0;
            }
            "q" | "exit" | "quit" => break,
            _ => {
                if let Ok(n) = input.parse::<usize>() {
                    // 数字：直接打开对应编号记录（并同步高亮）
                    if n >= 1 && n <= records.len() {
                        sel = n - 1;
                        clear_screen()?;
                        open_record(vault, &records[n - 1], n)?;
                        clear_screen()?;
                        last_rows = 0;
                        buf.clear();
                    } else {
                        println!("{}", ui::theme::warn(&format!("⚠ 编号超出范围（当前列表 1-{}）", records.len())));
                        last_rows = 0;
                    }
                } else {
                    // 其余输入视为搜索词
                    filter = Some(input);
                    sel = 0;
                    buf.clear();
                }
            }
        }
    }
    println!("{}", ui::theme::dim("再见！"));
    Ok(())
}

/// 清屏（切页用）：清空整个屏幕并把光标移到左上角，实现「吞没旧输出文字」。
/// 走缓冲终端，flush 一次性生效。
fn clear_screen() -> Result<(), String> {
    let term = ui::term();
    term.clear_screen()
        .map_err(|e| format!("清屏失败：{e}"))?;
    term.flush().map_err(|e| format!("清屏失败：{e}"))?;
    Ok(())
}

/// 设置菜单：切换主页显示模式（分页 / 一口气全部输出）
fn settings_menu(vault: &Vault) -> Result<(), String> {
    println!("\n{}", ui::theme::title("── 设置 ──"));
    let current = vault.display_mode();
    let items = vec![
        format!("分页显示（推荐，每页 {} 条）{}", PAGE_SIZE, if current == storage::DisplayMode::Paged { "  ✓ 当前" } else { "" }),
        format!("一口气全部输出（不换页，记录多时列表很长）{}", if current == storage::DisplayMode::Full { "  ✓ 当前" } else { "" }),
        format!("退出设置"),
    ];
    let choice = Select::new()
        .with_prompt("主页显示方式")
        .items(&items)
        .default(if current == storage::DisplayMode::Paged { 0 } else { 1 })
        .interact_on(&ui::term())
        .map_err(|_| "已取消".to_string())?;
    match choice {
        0 => {
            vault.set_display_mode(storage::DisplayMode::Paged)?;
            println!("{}", ui::theme::ok("✓ 已切换为分页显示"));
        }
        1 => {
            vault.set_display_mode(storage::DisplayMode::Full)?;
            println!("{}", ui::theme::ok("✓ 已切换为全部输出"));
        }
        _ => println!("{}", ui::theme::dim("已退出设置")),
    }
    Ok(())
}

/// 高亮选择式列表渲染：整块清空 → 标题 + 列表（高亮行反色）→ 分隔线，
/// 全部写入缓冲终端，flush 一次性输出，避免逐行刷新闪烁。
/// 提示行（MAIN_PROMPT）由 read_command 单独维护，不在此渲染（避免双行提示）。
fn render_select_list(
    records: &[Record],
    sel: usize,
    filter: &Option<String>,
    page_size: usize,
    last_rows: &mut usize,
) -> Result<(), String> {
    let term = ui::term();
    // Full 模式（一口气全部输出）：page_size 等于记录数 → 单页全量渲染，
    // 重绘时用清屏绝对定位，避免大列表滚动后 clear_last_lines 相对定位错位。
    let full_mode = !records.is_empty() && page_size >= records.len();
    let pages = records.len().div_ceil(page_size).max(1);
    let page = if records.is_empty() { 0 } else { sel / page_size };
    let start = page * page_size;
    let end = (start + page_size).min(records.len());

    // 标题（含总数/搜索词/页码）——Claude 风格：亮洋红标题 + 暗色页码
    let mut title = format!(" 密码库（共 {} 条", records.len());
    if let Some(kw) = filter {
        title.push_str(&format!("，搜索「{kw}」"));
    }
    title.push('）');
    let mut page_note = String::new();
    if pages > 1 {
        page_note = ui::theme::dim(&format!("  第 {}/{} 页", page + 1, pages));
    }
    let title = format!("──{}──{}", ui::theme::title(&title), page_note);

    let item_lines = if records.is_empty() { 1 } else { end - start };
    let rows = 1 + item_lines + 1; // 标题 + 记录/提示 + 分隔线（提示行在渲染区下一行，由 read_command 维护）

    if full_mode {
        // Full 模式：清屏后从头渲染（绝对定位，可靠）
        term.clear_screen().map_err(|e| format!("重绘失败：{e}"))?;
    } else if *last_rows > 0 {
        // 分页模式：清掉旧区域再重绘（缓冲序列，flush 时一次性生效）
        term.clear_last_lines(*last_rows)
            .map_err(|e| format!("重绘失败：{e}"))?;
    }
    let w = |s: &str| term.write_line(s).map_err(|e| format!("渲染失败：{e}"));
    w(&title)?;
    if records.is_empty() {
        match filter {
            Some(kw) => w(&ui::theme::dim(&format!("（没有匹配「{kw}」的记录）")))?,
            None => w(&ui::theme::dim("（还没有任何记录，按 A 新增）"))?,
        };
    } else {
        for (i, r) in records[start..end].iter().enumerate() {
            let idx = start + i;
            let line = format!("[{:>3}] {}", idx + 1, r.app_name);
            // 高亮行：反色加粗 + ❯ 前缀（Claude 风格）
            if idx == sel {
                w(&ui::theme::highlight(&format!("❯ {line}")))?;
            } else {
                w(&format!("  {line}"))?;
            }
        }
    }
    w(&ui::theme::divider())?;
    term.flush().map_err(|e| format!("渲染失败：{e}"))?;
    *last_rows = rows;
    Ok(())
}

/// 非终端环境：普通读行（无直接翻页/高亮，其余行为一致）
fn render_plain_list(
    records: &[Record],
    filter: &Option<String>,
    page_size: usize,
) -> Result<(), String> {
    let pages = records.len().div_ceil(page_size).max(1);
    let page = 0;
    let start = page * page_size;
    let end = (start + page_size).min(records.len());

    let mut title = format!("========== 密码库（共 {} 条", records.len());
    if let Some(kw) = filter {
        title.push_str(&format!("，搜索「{kw}」"));
    }
    title.push('）');
    if pages > 1 {
        title.push_str(&format!("  第 {}/{} 页", page + 1, pages));
    }
    println!("\n{title}==========");

    if records.is_empty() {
        match filter {
            Some(kw) => println!("（没有匹配「{kw}」的记录）"),
            None => println!("（还没有任何记录，输入 A 新增）"),
        }
    } else {
        for (i, r) in records[start..end].iter().enumerate() {
            println!("[{:>3}] {}", start + i + 1, r.app_name);
        }
        if pages > 1 {
            println!("…（共 {} 条，输入编号打开）", records.len());
        }
    }
    println!("------------------------------------------");
    Ok(())
}

/// 高亮选择模式指令读取：↑/↓ 移动高亮（返回 None 触发重绘），回车提交输入。
/// 返回 None 表示已移动高亮（调用方需重新渲染列表）。
fn read_command(
    reader: &ui::KeyReader,
    records_len: usize,
    sel: &mut usize,
    buf: &mut String,
) -> Result<Option<String>, String> {
    use ui::KeyPress;
    let mut out = std::io::stderr();
    // Claude 风格输入行：❯ 前缀 + 主提示（暗色）+ 已输入内容
    let prompt_line = format!(
        "{} {}",
        ui::theme::title("❯"),
        ui::theme::dim(MAIN_PROMPT)
    );
    loop {
        let _ = write!(out, "\r\x1b[2K{prompt_line} {buf}");
        let _ = out.flush();
        match reader.read()? {
            KeyPress::Char(c) => {
                // 长度防护：超过上限的字符忽略
                if buf.chars().count() < ui::MAX_INPUT {
                    buf.push(c);
                }
            }
            KeyPress::Backspace => {
                buf.pop();
            }
            // 移动高亮：上下逐条移动，跨页边界自动换页
            KeyPress::Up => {
                if *sel > 0 {
                    *sel -= 1;
                }
                return Ok(None);
            }
            KeyPress::Down => {
                if *sel + 1 < records_len {
                    *sel += 1;
                }
                return Ok(None);
            }
            // 整页跳转
            KeyPress::PageUp => {
                *sel = sel.saturating_sub(PAGE_SIZE);
                return Ok(None);
            }
            KeyPress::PageDown => {
                if records_len > 0 {
                    *sel = (*sel + PAGE_SIZE).min(records_len - 1);
                }
                return Ok(None);
            }
            KeyPress::Enter => return Ok(Some(buf.trim().to_string())),
            // Ctrl+C / Esc：退出
            KeyPress::Cancel => return Ok(Some("q".to_string())),
            _ => {}
        }
    }
}

/// 非终端环境：普通读行（无直接翻页，其余行为一致；结果截断到 MAX_INPUT）
fn read_line_fallback() -> Result<String, String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("无法读取输入：{e}"))?;
    Ok(line.trim().chars().take(ui::MAX_INPUT).collect())
}

/// 查看记录：完整字段 + 解密密码（默认掩码显示，V 暂时查看），可复制/修改/删除
fn open_record(vault: &Vault, rec: &Record, position: usize) -> Result<(), String> {
    let mut reveal = false;
    loop {
        clear_screen()?; // 切页：每次重绘都吞没旧输出（V/C/M/D 后重画）
        println!(
            "\n──{}──",
            ui::theme::title(&format!(" 记录 #{position}（{}） ", rec.app_name))
        );
        print_record(rec, vault, reveal);
        println!("{}", ui::theme::divider());
        let prompt = if reveal {
            "[V]隐藏密码 / [C]复制 / [M]修改 / [D]删除 / [回车]返回"
        } else {
            "[V]暂时查看密码 / [C]复制 / [M]修改 / [D]删除 / [回车]返回"
        };
        let choice: String = Input::new()
            .with_prompt(prompt)
            .allow_empty(true)
            .interact_text_on(&ui::term())
            .map_err(|_| "已退出".to_string())?;
        match choice.trim().to_ascii_lowercase().as_str() {
            "" => break,
            "v" => reveal = !reveal,
            "c" => copy_password(vault, rec)?,
            "m" => return change_one(vault, rec.id, position),
            "d" => {
                if confirm_delete(vault, rec, position)? {
                    return Ok(());
                }
            }
            _ => println!("{}", ui::theme::err("✗ 无法识别的命令")),
        }
    }
    Ok(())
}

fn print_record(rec: &Record, vault: &Vault, reveal: bool) {
    let pwd = match vault.decrypt(&rec.password_blob) {
        Ok(p) => p,
        Err(e) => format!("（无法解密：{e}）"),
    };
    let pwd_line = if reveal {
        pwd
    } else {
        format!("{}（V 暂时查看）", "•".repeat(pwd.chars().count()))
    };
    let f = |name: &str| ui::theme::field(name);
    println!("{}：{}", f("应用名称"), rec.app_name);
    println!("{}：{}", f("昵称"), rec.nick_name);
    println!("{}：{}", f("用户名"), rec.user_name);
    println!("{}：{}", f("ID"), rec.user_id);
    println!("{}：{}", f("密码"), pwd_line);
    println!("{}：{}", f("凭证应用"), rec.voucher);
    println!("{}：{}", f("注册凭证"), rec.register);
    println!("{}：{}", f("备注"), rec.remark);
    println!("{}：{}", f("最后修改"), rec.stamp);
}

fn copy_password(vault: &Vault, rec: &Record) -> Result<(), String> {
    let pwd = vault.decrypt(&rec.password_blob).map_err(|e| e.to_string())?;
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("无法访问剪贴板：{e}"))?;
    cb.set_text(pwd).map_err(|e| format!("复制失败：{e}"))?;
    println!("{}", ui::theme::ok("✓ 密码已复制到剪贴板"));
    Ok(())
}

/// 新增记录：按顺序引导输入 8 个字段
fn add_wizard(vault: &Vault) -> Result<(), String> {
    println!("\n{}", ui::theme::title("── 新增记录 ──"));
    println!("{}", ui::theme::dim("（直接回车可跳过非必填项）"));
    let app_name = loop {
        let v: String = Input::new()
            .with_prompt("应用名称（必填）")
            .interact_text_on(&ui::term())
            .map_err(|_| "已取消".to_string())?;
        // 长度防护：超长值截断到 MAX_INPUT
        let v: String = v.trim().chars().take(ui::MAX_INPUT).collect();
        if v.is_empty() {
            println!("{}", ui::theme::warn("⚠ 应用名称不能为空"));
            continue;
        }
        break v;
    };
    let r = RecordIn {
        app_name,
        nick_name: ask("昵称"),
        user_name: ask("用户名称"),
        user_id: ask("ID"),
        password: loop {
            let p = ui::secret_prompt("密码（必填）：")?;
            if p.is_empty() {
                println!("{}", ui::theme::warn("⚠ 密码不能为空"));
                continue;
            }
            break p;
        },
        voucher: ask("凭证应用"),
        register: ask("注册凭证"),
        remark: ask("备注"),
    };
    // 新增直接保存（无需确认，回车即完成）
    vault.add(&r)?;
    println!(
        "{} 回车可继续其他操作",
        ui::theme::ok(&format!("✓ 已添加「{}」", r.app_name))
    );
    Ok(())
}

fn ask(label: &str) -> String {
    let v: String = Input::new()
        .with_prompt(label)
        .allow_empty(true)
        .interact_text_on(&ui::term())
        .unwrap_or_default();
    // 长度防护：超长值截断到 MAX_INPUT
    v.trim().chars().take(ui::MAX_INPUT).collect()
}

/// 字段编辑：循环修改多个字段，X 保存 / Q 取消
fn change_one(vault: &Vault, id: i64, position: usize) -> Result<(), String> {
    let Some(rec) = vault.get(id)? else {
        println!("记录 #{position} 不存在");
        return Ok(());
    };
    let mut pwd_ok = true;
    let pwd = match vault.decrypt(&rec.password_blob) {
        Ok(p) => p,
        Err(_) => {
            pwd_ok = false;
            String::new()
        }
    };
    let mut fields: [String; 8] = [
        rec.app_name.clone(),
        rec.nick_name.clone(),
        rec.user_name.clone(),
        rec.user_id.clone(),
        pwd,
        rec.voucher.clone(),
        rec.register.clone(),
        rec.remark.clone(),
    ];

    loop {
        clear_screen()?; // 切页：每次重绘字段列表都吞没旧输出
        println!(
            "\n{}",
            ui::theme::title(&format!("── 修改记录 #{position} ──"))
        );
        for (i, name) in FIELD_NAMES.iter().enumerate() {
            println!("{} {}：{}", ui::theme::dim(&format!("[{i}]")), ui::theme::field(name), fields[i]);
        }
        println!("{}", ui::theme::dim("[X] 保存并退出 / [Q] 取消"));
        let choice: String = Input::new()
            .with_prompt("输入 0-7 或 X/Q")
            .allow_empty(true)
            .interact_text_on(&ui::term())
            .map_err(|_| "已取消".to_string())?;
        let choice = choice.trim().to_ascii_lowercase();
        match choice.as_str() {
            "x" | "" => {
                if !pwd_ok && fields[4].is_empty() {
                    println!("{}", ui::theme::warn("⚠ 注意：原密码无法解密，保存后密码将变为空"));
                    if !Confirm::new()
                        .with_prompt("仍要保存吗？")
                        .default(false)
                        .interact_on(&ui::term())
                        .map_err(|_| "已取消".to_string())?
                    {
                        println!("{}", ui::theme::dim("已取消"));
                        return Ok(());
                    }
                }
                let r = RecordIn {
                    app_name: fields[0].clone(),
                    nick_name: fields[1].clone(),
                    user_name: fields[2].clone(),
                    user_id: fields[3].clone(),
                    password: fields[4].clone(),
                    voucher: fields[5].clone(),
                    register: fields[6].clone(),
                    remark: fields[7].clone(),
                };
                vault.save(id, &r)?;
                println!("{}", ui::theme::ok("✓ 已保存，最后修改时间已更新"));
                return Ok(());
            }
            "q" => {
                println!("{}", ui::theme::dim("已取消修改"));
                return Ok(());
            }
            _ => {
                let Ok(i) = choice.parse::<usize>() else {
                    println!("{}", ui::theme::err("✗ 无法识别的输入，请输入 0-7 或 X/Q"));
                    continue;
                };
                if i >= 8 {
                    println!("{}", ui::theme::warn("⚠ 字段编号超出范围，请输入 0-7"));
                    continue;
                }
                if i == 4 {
                    fields[4] = ui::secret_prompt("新密码：")?;
                    pwd_ok = true;
                } else {
                    let label = format!("新{}（当前：{}）", FIELD_NAMES[i], fields[i]);
                    let v: String = Input::new()
                        .with_prompt(&label)
                        .allow_empty(true)
                        .interact_text_on(&ui::term())
                        .map_err(|_| "已取消".to_string())?;
                    // 长度防护：超长值截断到 MAX_INPUT
                    fields[i] = v.trim().chars().take(ui::MAX_INPUT).collect();
                }
            }
        }
    }
}

/// 确认删除并执行（作用于调用方传入的记录）
fn confirm_delete(vault: &Vault, rec: &Record, position: usize) -> Result<bool, String> {
    let confirm = Confirm::new()
        .with_prompt(format!(
            "确定删除 [{position}] {}？此操作不可撤销（回车=否，输入 y 确认）",
            rec.app_name
        ))
        .default(false)
        .interact_on(&ui::term())
        .map_err(|_| "已取消".to_string())?;
    if confirm {
        vault.delete(rec.id)?;
        println!("{}", ui::theme::ok("✓ 已删除"));
        Ok(true)
    } else {
        println!("{}", ui::theme::dim("已取消"));
        Ok(false)
    }
}
