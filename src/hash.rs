use sha2::{Digest, Sha256};

pub type Hash256 = [u8; 32];

pub const BYTES_PER_CHUNK: usize = 32;
pub const MAX_DEPTH: usize = 64;

pub fn hash(data: &[u8]) -> Hash256 {
    Sha256::digest(data).into()
}

pub fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Root of a fully zeroed subtree with `2^depth` leaves.
///
/// # Panics
///
/// Panics if `depth > MAX_DEPTH`.
pub const fn zero_hash(depth: usize) -> Hash256 {
    ZERO_HASHES[depth]
}

const ZERO_HASHES: [Hash256; MAX_DEPTH + 1] = [
    h("0000000000000000000000000000000000000000000000000000000000000000"),
    h("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    h("db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
    h("c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
    h("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
    h("9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
    h("d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1"),
    h("87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
    h("26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"),
    h("506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1"),
    h("ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
    h("6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220"),
    h("b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f"),
    h("df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e"),
    h("b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784"),
    h("d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb"),
    h("8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb"),
    h("8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab"),
    h("95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4"),
    h("f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f"),
    h("cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa"),
    h("8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c"),
    h("feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167"),
    h("e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7"),
    h("31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0"),
    h("21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544"),
    h("619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765"),
    h("7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4"),
    h("848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1"),
    h("8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636"),
    h("b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c"),
    h("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7"),
    h("c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff"),
    h("1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5"),
    h("2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d"),
    h("328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c"),
    h("bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327"),
    h("55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74"),
    h("f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76"),
    h("ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f"),
    h("6bfe8d2bcc4237b74a5047058ef455339ecd7360cb63bfbb8ee5448e6430ba04"),
    h("a7f23ce9181740dc220c814782654fee6aceb9f1ec9222c4e2467d0ab1680837"),
    h("aef9476c89590a2c8cc9b3b74f4967c757c49d9866a44bacf21fa2ed675ddfa2"),
    h("9a42bcad82f6a9e41284d808ead319f29f3b08209d680f0e2ce71510d071e205"),
    h("d1a66d354a67b9cf179571d8e5f97792716e8dd4ec44196839a3f7c6b74f8bac"),
    h("fafa3025f2f89509c2c71c74fba0cd92858ef49b0780fb5479746c8a9bfcb346"),
    h("3334a7c1e7f6705aa6011a6a949645016db4acde0ca9abd66dc79d8266423056"),
    h("0796fd75664faef744ee4e52d7271e2bbb769f91ed6f9b74d8b694f56606852c"),
    h("7ba3ae4a417fe8545b142bc89f4adcd7ae13941cbab7750b83e9f0a66d16be64"),
    h("788fafcc4aa520399adbaed195f8b12c4eb31ec10168e50aabc659a6aea516dc"),
    h("e833d7a67160e68bf4c9044a53077df2727ad00cf36f4949c7b681a912140cbb"),
    h("309eabf095dc6714f9f4d864bba5affae0b35ae2f5e3565bcc3a47b212767701"),
    h("226a8ebefa288665a644a50273335efbb610510f241b5b720c8a368d59a69a5d"),
    h("41abfd995425827625938131af0c4f33fe0bd4688c222c21fa9da8e89caa03f8"),
    h("442c642ef50fa1a667a6e6d105c77c5cc3fec8d7aa2570cf1a3077b503c38069"),
    h("a0a08dfc9b42d96c2de19b6d127b8ae136ddcf3e5ad0dce422c45a56f61f6a74"),
    h("7d348382af096dbe0bf086c7bb39b2a2c0bc36b621ab0c738e9885d731d81740"),
    h("3ab134751d191269026c86994eaa8b43a83b4ad1f6d0e77381c4e2974afbc8f6"),
    h("9a7452611db2d23eae26f9bdbb88958ef44c64d0fe987be9f726adf938f50f6c"),
    h("725c7f816037bfe452cd1e7ba35ac47edcb49a9a2b27aeca70dce483cb7ded1f"),
    h("2cea1af51fb28b62887c39998ac9fef4dfdeda1f07e071ba558a173afd06cbc3"),
    h("ff1d59f98b6c551d95089357057d5c8be26402279e9df0b1df1a10b72bf3927f"),
    h("2f8a181f7c99dd215a7529bfe296a9603a1446737186d21aeb8bc7ae59e1fd21"),
    h("ecc502c9b1145f3950cb7d3e3842446f81a4f0df1df537cee139ef64ea984bd9"),
    h("c885c236140249c9e1640e5e99fb972d81fbb31ea5e29fbdde063627f0d6bdc8"),
];

const fn h(s: &str) -> Hash256 {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex digit"),
        }
    }
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

pub(crate) fn length_chunk(len: u64) -> Hash256 {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&len.to_le_bytes());
    chunk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(h: &Hash256) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_digests() {
        assert_eq!(hex(&hash(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&zero_hash(1)), "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    }

    #[test]
    fn zero_hashes_chain() {
        assert_eq!(zero_hash(0), [0u8; 32]);
        for d in 1..=MAX_DEPTH {
            assert_eq!(zero_hash(d), hash_pair(&zero_hash(d - 1), &zero_hash(d - 1)));
        }
    }
}
