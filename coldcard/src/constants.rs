pub const AFC_PUBKEY: u8 = 0x01;
pub const AFC_SEGWIT: u8 = 0x02;
pub const AFC_BECH32: u8 = 0x04;
pub const AFC_SCRIPT: u8 = 0x08;
pub const AFC_WRAPPED: u8 = 0x10;

pub const USER_AUTH_SHOW_QR: u8 = 0x80;

pub const CHUNK_SIZE: usize = 63;

pub const MAX_BLK_LEN: usize = 2048;
pub const MAX_MSG_LEN: usize = 4 + 4 + 4 + MAX_BLK_LEN;

pub const STXN_FINALIZE: u32 = 0x01;
pub const STXN_VISUALIZE: u32 = 0x02;
pub const STXN_SIGNED: u32 = 0x04;
