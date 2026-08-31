//! 交互向导：初始化（主密码 + 恢复路径设置）与解锁（含恢复菜单）。
//! 主程序与迁移程序共用，保证两处流程一致。

use std::io::Write;

use dialoguer::{Confirm, Input, Select};

use crate::storage::{self, RecoveryOpts, Vault};

/// 供 dialoguer 使用的缓冲终端。
///
/// 普通 `Term::stderr()` 的每次写操作（清行/移动光标/输出行）都会单独刷新控制台，
/// 而 dialoguer 的选择菜单每次按键都是「整块清空 → 逐行重绘」，多次刷新会让中间
/// 状态暴露在屏幕上造成**闪烁**。缓冲终端把所有序列先写入内存，`flush()` 时一次性
/// 输出，屏幕只见最终帧，从根本上消除闪烁。
pub fn term() -> console::Term {
    console::Term::buffered_stderr()
}

/// 启动时调用：把 Windows 控制台代码页设为 UTF-8 并启用 VT 转义序列，避免中文乱码。
/// stdout 与 stderr 都启用 VT（stdout 的 println 输出 ANSI 颜色需要它）。
pub fn setup_console() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleCP, SetConsoleMode, SetConsoleOutputCP,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        };
        const CP_UTF8: u32 = 65001;
        // 输出/输入代码页：让所有按字节写出的内容按 UTF-8 解读
        let _ = SetConsoleOutputCP(CP_UTF8);
        let _ = SetConsoleCP(CP_UTF8);
        // 启用 VT 转义序列（密码输入行的整行重绘需要；stdout 也需要以便 println 颜色生效）
        for handle in [GetStdHandle(STD_ERROR_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE)] {
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

/// Claude Code 风格主题：终端下自动着色，管道/重定向下自动无色。
/// 统一用 for_stderr 判定（UI 主输出在 stderr；stdout 也已启用 VT）。
pub mod theme {
    use console::style;

    fn st(s: &str) -> console::StyledObject<&str> {
        style(s).for_stderr()
    }

    /// 标题（亮洋红加粗）
    pub fn title(s: &str) -> String {
        format!("{}", st(s).magenta().bright().bold())
    }
    /// 字段名（青色）
    pub fn field(s: &str) -> String {
        format!("{}", st(s).cyan())
    }
    /// 成功反馈（绿色）
    pub fn ok(s: &str) -> String {
        format!("{}", st(s).green())
    }
    /// 警告（黄色）
    pub fn warn(s: &str) -> String {
        format!("{}", st(s).yellow())
    }
    /// 错误（红色）
    pub fn err(s: &str) -> String {
        format!("{}", st(s).red())
    }
    /// 次要信息（暗色）
    pub fn dim(s: &str) -> String {
        format!("{}", st(s).dim())
    }
    /// 高亮行（反色加粗）
    pub fn highlight(s: &str) -> String {
        format!("{}", st(s).reverse().bold())
    }
    /// 分隔线
    pub fn divider() -> String {
        format!("{}", st(&"─".repeat(46)).dim())
    }
}

/// 输入机密信息：每个字符以黑点「•」显示（有输入反馈），
/// 按 Tab（或 Ctrl+E）可暂时明文查看，再按一次隐藏；Esc/Ctrl+C 取消。
/// 提示符经 Rust std 输出（对控制台走 WriteConsoleW，中文安全）。
pub fn secret_prompt(prompt: &str) -> Result<String, String> {
    let mut err = std::io::stderr();
    // 前导换行只输出一次（如 banner 与输入提示之间的空行）；
    // 重绘时使用不含换行的提示符，避免每次按键写入 \n 导致光标逐行下移。
    let (lead, clean) = match prompt.strip_prefix('\n') {
        Some(rest) => ("\n", rest),
        None => ("", prompt),
    };
    err.write_all(lead.as_bytes())
        .map_err(|e| format!("无法显示提示：{e}"))?;
    err.write_all(clean.as_bytes())
        .map_err(|e| format!("无法显示提示：{e}"))?;
    err.flush().map_err(|e| format!("无法刷新输出：{e}"))?;
    let result = read_masked(clean);
    // 输入结束后换行
    let _ = err.write_all(b"\r\n");
    let _ = err.flush();
    result
}

/// 统一按键类型（掩码输入与主界面指令共用）
pub enum KeyPress {
    Char(char),
    Enter,
    Backspace,
    /// Tab 或 Ctrl+E（Ctrl+V 在 Windows Terminal 被粘贴占用，仅作兼容别名）
    Toggle,
    Up,
    Down,
    PageUp,
    PageDown,
    /// Esc / Ctrl+C
    Cancel,
    Other,
}

/// 按键读取器：读取期间关闭终端回显（Windows 直接操作控制台输入模式）
pub struct KeyReader {
    term: console::Term,
    #[cfg(windows)]
    _guard: EchoGuard,
}

#[cfg(windows)]
struct EchoGuard {
    input: windows_sys::Win32::Foundation::HANDLE,
    orig: u32,
}

#[cfg(windows)]
impl EchoGuard {
    fn new() -> Result<Self, String> {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
            ENABLE_PROCESSED_INPUT, STD_INPUT_HANDLE,
        };
        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut orig: u32 = 0;
        if unsafe { GetConsoleMode(input, &mut orig) } == 0 {
            return Err("非终端".into());
        }
        // 关闭回显/行缓冲/processed：终端不再自动回显，Ctrl+C 以按键形式到达
        let target = orig & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
        unsafe {
            SetConsoleMode(input, target);
        }
        Ok(Self { input, orig })
    }
}

#[cfg(windows)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        unsafe {
            use windows_sys::Win32::System::Console::SetConsoleMode;
            SetConsoleMode(self.input, self.orig);
        }
    }
}

impl KeyReader {
    /// 创建读取器；非终端（管道/重定向）时返回 Err
    pub fn new() -> Result<Self, String> {
        #[cfg(windows)]
        let guard = EchoGuard::new()?;
        Ok(Self {
            term: console::Term::stderr(),
            #[cfg(windows)]
            _guard: guard,
        })
    }

    /// 读取一个按键
    pub fn read(&self) -> Result<KeyPress, String> {
        use console::Key;
        match self.term.read_key() {
            // Ctrl+V / Ctrl+E / Tab：暂时查看切换
            Ok(Key::Char('\x16')) | Ok(Key::Char('\x05')) | Ok(Key::Tab) => {
                Ok(KeyPress::Toggle)
            }
            Ok(Key::Char(c)) if !c.is_control() => Ok(KeyPress::Char(c)),
            Ok(Key::Enter) => Ok(KeyPress::Enter),
            Ok(Key::Backspace) => Ok(KeyPress::Backspace),
            Ok(Key::ArrowUp) => Ok(KeyPress::Up),
            Ok(Key::ArrowDown) => Ok(KeyPress::Down),
            Ok(Key::PageUp) => Ok(KeyPress::PageUp),
            Ok(Key::PageDown) => Ok(KeyPress::PageDown),
            // Ctrl+C 在 Windows 可能以 '\x03' 字符到达
            Ok(Key::CtrlC) | Ok(Key::Char('\x03')) | Ok(Key::Escape) => Ok(KeyPress::Cancel),
            Err(e) => Err(format!("无法读取输入：{e}")),
            _ => Ok(KeyPress::Other),
        }
    }
}

/// 输入长度上限（字符数）：防止意外超长输入导致界面渲染错乱/资源消耗。
/// 适用于搜索框、字段值、密码等所有用户输入。
pub const MAX_INPUT: usize = 200;

/// 在 stderr 的当前行上重绘指定文本：先清空整行并把光标移至行首，再写入文本。
///
/// Windows 下用 Win32 API 清当前行（不依赖 `\r\x1b[2K` ANSI），
/// 避免某些终端（conhost/ISE）不解析 VT 序列时每字符换行/乱码；
/// 非 Windows 回退 ANSI 清行。掩码输入与主界面指令行共用。
pub fn redraw_line(out: &mut impl Write, text: &str) {
    #[cfg(windows)]
    {
        unsafe {
            use windows_sys::Win32::System::Console::{
                FillConsoleOutputAttribute, FillConsoleOutputCharacterW, GetConsoleScreenBufferInfo,
                GetStdHandle, SetConsoleCursorPosition, CONSOLE_SCREEN_BUFFER_INFO, STD_ERROR_HANDLE,
                COORD,
            };
            let handle = GetStdHandle(STD_ERROR_HANDLE);
            let mut csbi: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
            if GetConsoleScreenBufferInfo(handle, &mut csbi) != 0 {
                // 清当前行（从行首到窗口右缘）
                let width = (csbi.srWindow.Right - csbi.srWindow.Left + 1) as u32;
                let pos = COORD { X: 0, Y: csbi.dwCursorPosition.Y };
                let mut written: u32 = 0;
                let mut wrote_attr: u32 = 0;
                FillConsoleOutputCharacterW(handle, b' ' as u16, width, pos, &mut written);
                // 必须同时恢复颜色属性：否则空格会继承高亮行的反色（白色）背景，残留白色块
                FillConsoleOutputAttribute(handle, csbi.wAttributes, width, pos, &mut wrote_attr);
                SetConsoleCursorPosition(handle, pos);
            }
        }
        let _ = write!(out, "{text}");
    }
    #[cfg(not(windows))]
    {
        let _ = write!(out, "\r\x1b[2K{text}");
    }
}

/// 掩码输入：黑点反馈 + Tab 暂时查看
fn read_masked(prompt: &str) -> Result<String, String> {
    let reader = match KeyReader::new() {
        Ok(r) => r,
        Err(_) => return read_line_fallback(),
    };
    let mut out = std::io::stderr();
    let mut buf = String::new();
    let mut revealed = false;
    loop {
        let body = if revealed {
            format!("{buf}  （显示中，Tab 隐藏）")
        } else {
            format!("{}  （Tab 暂时查看）", "•".repeat(buf.chars().count()))
        };
        redraw_line(&mut out, &format!("{prompt}{body}"));
        let _ = out.flush();
        match reader.read()? {
            KeyPress::Toggle => revealed = !revealed,
            KeyPress::Char(c) => {
                // 长度防护：超过上限的字符忽略（防止超长输入撑坏界面）
                if buf.chars().count() < MAX_INPUT {
                    buf.push(c);
                }
            }
            KeyPress::Backspace => {
                buf.pop();
            }
            KeyPress::Enter => break Ok(buf),
            KeyPress::Cancel => break Err("已取消".into()),
            _ => {}
        }
    }
}

/// 非终端（管道/重定向）时的降级方案：普通读行（结果截断到 MAX_INPUT）
fn read_line_fallback() -> Result<String, String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("无法读取输入：{e}"))?;
    Ok(line.trim_end_matches(['\r', '\n']).chars().take(MAX_INPUT).collect())
}

/// 首次使用向导：设置主密码 + 可选恢复路径，然后建库。
/// 返回主密码（供调用方直接解锁，避免重复输入）。
pub fn setup_wizard(db_path: &str) -> Result<String, String> {
    show_banner();
    println!("\n{}", theme::title("── 首次使用 · 创建密码库 ──"));
    println!("{}", theme::dim(&format!("数据库：{db_path}")));
    println!("{}", theme::dim("- 主密码用于加密全部数据，不会保存为明文"));
    println!("{}", theme::dim("- 忘记主密码时，可用设置的恢复路径（机器码 / 密保问卷）找回"));
    if !Confirm::new()
        .with_prompt("是否开始设置？")
        .default(true)
        .interact_on(&term())
        .map_err(|_| "已取消".to_string())?
    {
        return Err("已取消设置".into());
    }

    // 主密码
    let master = loop {
        let p1 = secret_prompt("设置主密码：")?;
        if p1.is_empty() {
            println!("{}", theme::warn("⚠ 主密码不能为空，请重新设置"));
            continue;
        }
        let p2 = secret_prompt("请再次输入主密码：")?;
        if p1 != p2 {
            println!("{}", theme::warn("⚠ 两次输入不一致，请重新设置"));
            continue;
        }
        break p1;
    };

    // 恢复路径
    let mut recovery = RecoveryOpts {
        machine_binding: false,
        qa_pairs: vec![],
    };
    println!("\n{}", theme::title("── 恢复路径设置 ──"));
    println!("{}", theme::dim("（可选，至少建议设置一个）"));
    if Confirm::new()
        .with_prompt("绑定本机机器码作为恢复路径？（注意：任何能接触本机的人可凭此解锁）")
        .default(false)
        .interact_on(&term())
        .map_err(|_| "已取消".to_string())?
    {
        recovery.machine_binding = true;
        println!("{}", theme::ok("✓ 已绑定机器码恢复路径"));
    }

    loop {
        let items = ["身份证号？", "手机号码？", "自定义问题", "完成设置"];
        let choice = Select::new()
            .with_prompt("添加密保问题（忘记主密码时回答正确即可恢复）")
            .items(items)
            .default(0)
            .interact_on(&term())
            .map_err(|_| "已取消".to_string())?;
        match choice {
            0 => qa_add(&mut recovery, "你的身份证号是什么？".into())?,
            1 => qa_add(&mut recovery, "你的手机号码是什么？".into())?,
            2 => {
                let q: String = Input::new()
                    .with_prompt("请输入自定义问题（例如：你的生日是？）")
                    .interact_text_on(&term())
                    .map_err(|_| "已取消".to_string())?;
                let q = q.trim().to_string();
                if q.is_empty() {
                    println!("{}", theme::warn("⚠ 问题不能为空"));
                    continue;
                }
                qa_add(&mut recovery, q)?;
            }
            _ => break,
        }
    }

    storage::init(db_path, &master, &recovery)?;
    println!(
        "\n{}",
        theme::ok("✓ 密码库创建完成！请牢记主密码与恢复答案。")
    );
    Ok(master)
}

fn qa_add(recovery: &mut RecoveryOpts, question: String) -> Result<(), String> {
    let answer = loop {
        let a1 = secret_prompt(&format!("回答问题「{question}」："))?;
        if a1.is_empty() {
            println!("{}", theme::warn("⚠ 答案不能为空"));
            continue;
        }
        let a2 = secret_prompt("请再次输入答案：")?;
        if a1 != a2 {
            println!("{}", theme::warn("⚠ 两次输入不一致，请重试"));
            continue;
        }
        break a1;
    };
    recovery.qa_pairs.push((question, answer));
    println!("{}", theme::ok("✓ 已添加密保问题"));
    Ok(())
}

/// 启动横幅：大号 ASCII Art 标题（PSWD）+ 作者/版本/仓库信息。
/// 启动时先清屏，保证终端干净；版本号从 Cargo.toml 动态读取。
pub fn show_banner() {
    let version = env!("CARGO_PKG_VERSION");
    // 启动清屏：吞没上次会话的终端残留输出
    let _ = clear_screen();

    // 大号 ASCII Art 标题：FIGlet slant 字体（正宗 slant.flf 字形，6 行高）
    const ART_P: [&str; 6] = [
        "    ____ ",
        "   / __ \\",
        "  / /_/ /",
        " / ____/ ",
        "/_/      ",
        "         ",
    ];
    const ART_S: [&str; 6] = [
        "   _____",
        "  / ___/",
        "  \\__ \\ ",
        " ___/ / ",
        "/____/  ",
        "        ",
    ];
    const ART_W: [&str; 6] = [
        " _       __",
        "| |     / /",
        "| | /| / / ",
        "| |/ |/ /  ",
        "|__/|__/   ",
        "           ",
    ];
    const ART_D: [&str; 6] = [
        "    ____ ",
        "   / __ \\",
        "  / / / /",
        " / /_/ / ",
        "/_____/  ",
        "         ",
    ];

    // 按行拼接（字母间 1 空格），保证四字母垂直对齐
    let art: Vec<String> = (0..6)
        .map(|i| format!("{} {} {} {}", ART_P[i], ART_S[i], ART_W[i], ART_D[i]))
        .collect();
    let art_width = art[0].len();

    // 终端列宽（居中显示）；stdout 非终端时回退 80
    let cols = console::Term::stdout()
        .size_checked()
        .map(|(_, c)| c as usize)
        .unwrap_or(80);
    let pad = cols.saturating_sub(art_width) / 2;

    // 大标题（亮洋红加粗）
    println!();
    for line in &art {
        println!("{}{}", " ".repeat(pad), theme::title(line));
    }
    println!();

    // 信息行（居中，作者/版本/仓库）
    fn center(s: &str, cols: usize) -> String {
        let w = console::strip_ansi_codes(s)
            .chars()
            .map(|c| if ('\u{4e00}'..='\u{9fff}').contains(&c) { 2 } else { 1 })
            .sum::<usize>();
        let p = cols.saturating_sub(w) / 2;
        format!("{}{}", " ".repeat(p), s)
    }
    println!("{}", center(&format!("{} {}", theme::field("作者"), theme::dim("D BOY")), cols));
    println!("{}", center(&format!("{} {}", theme::field("版本"), theme::dim(&format!("v{version}"))), cols));
    println!("{}", center(&format!("{} {}", theme::field("仓库"), theme::dim("github.com/dboycht/pswd")), cols));
    println!();
}

/// 清屏：清空整个屏幕并把光标移到左上角。
///
/// Windows 下直接用 Win32 控制台 API（FillConsoleOutputCharacterW + SetConsoleCursorPosition），
/// **不依赖 VT/ANSI 转义**，在任何 Windows 控制台（conhost / Windows Terminal / ISE）都可靠；
/// 非 Windows 平台回退到 ANSI 清屏序列。
pub fn clear_screen() -> Result<(), String> {
    #[cfg(windows)]
    {
        unsafe {
            use windows_sys::Win32::System::Console::{
                FillConsoleOutputAttribute, FillConsoleOutputCharacterW, GetConsoleScreenBufferInfo,
                GetStdHandle, SetConsoleCursorPosition, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
                COORD,
            };
            let handle = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut csbi: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
            if GetConsoleScreenBufferInfo(handle, &mut csbi) == 0 {
                return Err("清屏失败：无法读取控制台信息".into());
            }
            // 清空当前可见窗口区域（从窗口顶部到光标所在行数）
            let window_rows = (csbi.srWindow.Bottom - csbi.srWindow.Top + 1) as u32;
            let cells = csbi.dwSize.X as u32 * window_rows;
            let top = COORD { X: 0, Y: csbi.srWindow.Top };
            let mut written: u32 = 0;
            let mut wrote_attr: u32 = 0;
            FillConsoleOutputCharacterW(handle, b' ' as u16, cells, top, &mut written);
            // 必须同时恢复颜色属性：否则空格会继承高亮行的反色（白色）背景，残留白色块
            FillConsoleOutputAttribute(handle, csbi.wAttributes, cells, top, &mut wrote_attr);
            SetConsoleCursorPosition(handle, top);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let term = term();
        term.clear_screen().map_err(|e| format!("清屏失败：{e}"))?;
        term.flush().map_err(|e| format!("清屏失败：{e}"))?;
        Ok(())
    }
}

/// 解锁流程：主密码优先，失败后进入恢复菜单
pub fn unlock_flow(db_path: &str) -> Result<Vault, String> {
    show_banner();
    let pw = secret_prompt("\n主密码：")?;
    match storage::open(db_path, &pw) {
        Ok(vault) => {
            println!("{}", theme::ok("✓ 解锁成功"));
            Ok(vault)
        }
        Err(storage::UnlockError::WrongCredential) => {
            println!("{}", theme::err("✗ 主密码错误。"));
            recovery_menu(db_path)
        }
        Err(e) => Err(e.to_string()),
    }
}

/// 恢复菜单：机器码 / 密保问卷
fn recovery_menu(db_path: &str) -> Result<Vault, String> {
    let has_machine = storage::machine_recovery_available(db_path);
    let questions = storage::qa_questions(db_path);
    if !has_machine && questions.is_empty() {
        return Err("未配置任何恢复路径，无法解锁数据。".into());
    }

    let mut items: Vec<String> = Vec::new();
    if has_machine {
        items.push("使用本机机器码恢复".into());
    }
    items.extend(questions.iter().map(|q| format!("回答密保问题：{q}")));
    items.push("退出".into());

    let choice = Select::new()
        .with_prompt("请选择恢复方式")
        .items(&items)
        .default(0)
        .interact_on(&term())
        .map_err(|_| "已取消".to_string())?;
    if choice == items.len() - 1 {
        return Err("已退出。".into());
    }

    let vault = if has_machine && choice == 0 {
        println!("正在读取本机机器码…");
        storage::recover_with_machine(db_path).map_err(|e| e.to_string())?
    } else {
        let qi = choice - usize::from(has_machine);
        let answer = secret_prompt(&format!("回答「{}」：", questions[qi]))?;
        storage::recover_with_qa(db_path, qi, &answer).map_err(|e| e.to_string())?
    };
    println!("{}", theme::ok("✓ 恢复成功！"));

    // 恢复后建议立即重设主密码
    if Confirm::new()
        .with_prompt("是否立即重设主密码？")
        .default(true)
        .interact_on(&term())
        .map_err(|_| "已取消".to_string())?
    {
        let p1 = secret_prompt("新主密码：")?;
        let p2 = secret_prompt("请再次输入新主密码：")?;
        if !p1.is_empty() && p1 == p2 {
            vault.reset_master(&p1)?;
            println!("{}", theme::ok("✓ 主密码已更新"));
        } else {
            println!("{}", theme::warn("⚠ 输入无效或两次不一致，主密码未修改"));
        }
    }
    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// banner 的 ASCII Art（FIGlet slant 字体）：每个字母必须 6 行、无空行、宽度 ≤16（slant 最大宽）
    #[test]
    fn banner_art_slant_shape_valid() {
        const ART_P: [&str; 6] = [
            "    ____ ", "   / __ \\", "  / /_/ /", " / ____/ ", "/_/      ", "         ",
        ];
        const ART_S: [&str; 6] = [
            "   _____", "  / ___/", "  \\__ \\ ", " ___/ / ", "/____/  ", "        ",
        ];
        const ART_W: [&str; 6] = [
            " _       __", "| |     / /", "| | /| / / ", "| |/ |/ /  ", "|__/|__/   ", "           ",
        ];
        const ART_D: [&str; 6] = [
            "    ____ ", "   / __ \\", "  / / / /", " / /_/ / ", "/_____/  ", "         ",
        ];
        for art in [&ART_P, &ART_S, &ART_W, &ART_D] {
            assert_eq!(art.len(), 6, "slant 字母必须 6 行");
            for line in art {
                assert!(!line.is_empty(), "slant 字母不应有空字符串行");
                assert!(line.len() <= 16, "slant 字母行宽超过最大宽度 16");
            }
        }
        // 拼接顺序不产生换行字符
        let joined: Vec<String> = (0..6)
            .map(|i| format!("{} {} {} {}", ART_P[i], ART_S[i], ART_W[i], ART_D[i]))
            .collect();
        for line in &joined {
            assert!(!line.contains('\n'), "拼接行不应含换行");
        }
        assert!(joined[0].len() > 30, "大标题应足够宽");
    }
}
