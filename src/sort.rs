//! 排序规则（移植自 pswd2.py 的 sort_key）：
//! 1. 英文/数字开头排最前，按字母序
//! 2. 中文开头排其后，按拼音排序
//! 3. 其他字符最后

use pinyin::ToPinyin;

/// 返回排序键 (分类, 排序文本)；Rust 元组按元素依次比较，与 Python 的元组排序一致
pub fn sort_key(text: &str) -> (u8, String) {
    let text = text.trim();
    match text.chars().next() {
        Some(c) if c.is_ascii_alphanumeric() => (0, text.to_lowercase()),
        Some(c) if ('\u{4e00}'..='\u{9fff}').contains(&c) => (1, pinyin_text(text).to_lowercase()),
        _ => (2, text.to_lowercase()),
    }
}

/// 整段文本转拼音（无拼音字符原样保留，对齐 Python lazy_pinyin 的行为）
fn pinyin_text(text: &str) -> String {
    let mut out = String::new();
    for (ch, py) in text.chars().zip(text.to_pinyin()) {
        match py {
            Some(p) => out.push_str(p.plain()),
            None => out.push(ch),
        }
    }
    out
}

/// 拼音首字母（非汉字字符原样保留），如「微信」→「wx」
fn pinyin_initials(text: &str) -> String {
    let mut out = String::new();
    for (ch, py) in text.chars().zip(text.to_pinyin()) {
        match py {
            Some(p) => out.push_str(p.first_letter()),
            None => out.push(ch),
        }
    }
    out
}

/// 子序列匹配：needle 的字符按顺序出现在 haystack 中（允许跳跃，不要求连续）
pub fn is_subsequence(haystack: &str, needle: &str) -> bool {
    let mut rest = haystack.chars();
    needle.chars().all(|c| rest.any(|h| h == c))
}

/// 模糊匹配：关键词作为子序列出现在 原文 / 整段拼音 / 拼音首字母 任一形式中。
/// 例：「wx」匹配「微信」（首字母 weixin）、「ggl」匹配「google」、「支宝」匹配「支付宝」。
pub fn fuzzy_matches(text: &str, keyword: &str) -> bool {
    let kw = keyword.trim().to_lowercase();
    if kw.is_empty() {
        return true;
    }
    let lower = text.to_lowercase();
    is_subsequence(&lower, &kw)
        || is_subsequence(&pinyin_text(text).to_lowercase(), &kw)
        || is_subsequence(&pinyin_initials(text).to_lowercase(), &kw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_and_digits_first() {
        assert_eq!(sort_key("wechat"), (0, "wechat".to_string()));
        assert_eq!(sort_key("12306"), (0, "12306".to_string()));
    }

    #[test]
    fn chinese_sorted_by_pinyin() {
        let mut names = vec!["微信", "支付宝", "百度"];
        names.sort_by_key(|n| sort_key(n));
        // 拼音：baidu < weixin < zhifubao
        assert_eq!(names, vec!["百度", "微信", "支付宝"]);
    }

    #[test]
    fn mixed_groups_ordered() {
        let mut names = vec!["@杂项", "微信", "wechat", "百度"];
        names.sort_by_key(|n| sort_key(n));
        assert_eq!(names, vec!["wechat", "百度", "微信", "@杂项"]);
    }

    #[test]
    fn empty_and_special_last() {
        assert_eq!(sort_key(""), (2, String::new()));
        assert_eq!(sort_key("!!!"), (2, "!!!".to_string()));
        assert_eq!(sort_key("(测试)"), (2, "(测试)".to_string()));
    }

    #[test]
    fn case_insensitive_english() {
        assert_eq!(sort_key("WeChat").1, "wechat");
    }

    #[test]
    fn fuzzy_subsequence_and_pinyin() {
        // 原文子序列（含连续包含）
        assert!(fuzzy_matches("微信", "微信"));
        assert!(fuzzy_matches("Google 邮箱", "ggl邮箱"));
        // 拼音首字母
        assert!(fuzzy_matches("微信", "wx"));
        assert!(fuzzy_matches("百度", "bd"));
        // 整段拼音
        assert!(fuzzy_matches("微信", "weixin"));
        assert!(fuzzy_matches("淘宝", "taobao"));
        // 顺序必须一致，乱序不匹配
        assert!(!fuzzy_matches("微信", "xw"));
        assert!(!fuzzy_matches("google", "lgo"));
        assert!(!fuzzy_matches("google", "gz"));
        // 大小写不敏感
        assert!(fuzzy_matches("Google", "GGL"));
        // 空关键词匹配一切
        assert!(fuzzy_matches("任意", "  "));
    }

    #[test]
    fn is_subsequence_basic() {
        assert!(is_subsequence("weixin", "wx"));
        assert!(is_subsequence("baidu", "bd"));
        assert!(!is_subsequence("wx", "xw"));
        assert!(is_subsequence("abc", "abc"));
        assert!(!is_subsequence("abc", "abcd"));
        assert!(is_subsequence("", ""));
    }
}
