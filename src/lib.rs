//! 密码管理器核心库：加密、存储、排序、交互向导。
//! 主程序（main.rs）与旧数据迁移程序（bin/migrate_legacy.rs）共用。

pub mod crypto;
pub mod migrate;
pub mod sort;
pub mod storage;
pub mod ui;
