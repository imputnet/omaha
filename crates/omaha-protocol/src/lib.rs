//! Types for Chromium's update protocol (Omaha).

mod id;
mod version;

pub use id::{CRX_ID_LEN, is_valid_crx_id};
pub use version::{ParseVersionError, Version};
