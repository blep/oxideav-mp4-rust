#![no_main]

//! CENC cipher-path fuzzing (ISO/IEC 23001-7:2016) — three arms:
//!
//! 1. **Encrypt∘decrypt identity under arbitrary-but-valid crypto
//!    metadata.** The recipe picks one of the four §10 schemes
//!    (`cenc` / `cbc1` / `cens` / `cbcs`), a structurally valid
//!    `tenc` for it (matching FullBox version, per-sample 8/16-byte
//!    IV or constant IV per the §9.1 supply discipline, a non-zero
//!    §9.6 pattern pair for the pattern schemes), a recipe-driven
//!    subsample partition of the payload, key + IV bytes, and runs
//!    `encrypt_sample_in_place` → `decrypt_sample_in_place`. When
//!    encryption accepts the inputs, decryption MUST accept the same
//!    arguments and reproduce the plaintext byte-exactly.
//!
//! 2. **Hostile plan walking.** Raw, unvalidated subsample maps
//!    (attacker u16/u32 fields) + an arbitrary `sample_len` through
//!    `plan_sample_cipher` — Ok or Err, never a panic and never an
//!    allocation beyond what the input backs.
//!
//! 3. **Hostile `senc` / `seig` parsing** at every §7.2.3 IV width,
//!    plus `CencSchemeDecision::new` over arbitrary scheme × tenc
//!    combinations (mismatched versions, missing patterns, reserved
//!    isProtected values must be rejected structurally).

use libfuzzer_sys::fuzz_target;
use oxideav_mp4::cenc::{self, CencScheme, CencSchemeDecision, IvSupply, SubsampleEntry, TencBox};
use oxideav_mp4::cenc_cipher;
use oxideav_mp4_fuzz::Recipe;

fuzz_target!(|data: &[u8]| {
    let mut r = Recipe::new(data);

    let scheme = match r.u8() % 4 {
        0 => CencScheme::Cenc,
        1 => CencScheme::Cbc1,
        2 => CencScheme::Cens,
        _ => CencScheme::Cbcs,
    };
    let version = if matches!(scheme, CencScheme::Cenc | CencScheme::Cbc1) {
        0
    } else {
        1
    };

    // §9.1 IV supply: per-sample 8/16, or (v1 only) constant 8/16.
    let use_constant = version == 1 && r.u8() & 1 == 1;
    let per_sample_iv_size = if use_constant {
        0
    } else if r.u8() & 1 == 1 {
        16
    } else {
        8
    };
    let constant_iv = if use_constant {
        Some(if r.u8() & 1 == 1 {
            r.take_exact(16)
        } else {
            r.take_exact(8)
        })
    } else {
        None
    };
    // §9.6 pattern pair (non-zero for the pattern schemes).
    let (crypt, skip) = if version == 1 {
        (1 + r.u8() % 9, r.u8() % 10)
    } else {
        (0, 0)
    };

    let mut kid = [0u8; 16];
    kid.copy_from_slice(&r.take_exact(16));
    let tenc = TencBox {
        version,
        default_is_protected: 1,
        default_per_sample_iv_size: per_sample_iv_size,
        default_kid: kid,
        default_crypt_byte_block: crypt,
        default_skip_byte_block: skip,
        default_constant_iv: constant_iv,
    };
    let Ok(decision) = CencSchemeDecision::new(scheme, tenc) else {
        // Structural rejection of a combination this recipe allowed —
        // fine (e.g. a degenerate pattern pair); nothing to cipher.
        return;
    };

    let mut key = [0u8; 16];
    key.copy_from_slice(&r.take_exact(16));
    let per_sample_iv: Option<Vec<u8>> = match decision.iv_supply() {
        IvSupply::PerSample { size } => Some(r.take_exact(size as usize)),
        _ => None,
    };

    // Payload + optional subsample partition. Protected runs are
    // 16-aligned half the time so the CBC arms get through; the
    // unaligned other half must be *rejected* (Err), never mangled.
    let payload_len = 1 + (r.u16() % 2048) as usize;
    let mut subsamples: Option<Vec<SubsampleEntry>> = None;
    let mut data;
    if r.u8() & 1 == 1 {
        let n_sub = 1 + (r.u8() % 4) as usize;
        let align16 = r.u8() & 1 == 1;
        let mut list = Vec::with_capacity(n_sub);
        let mut total = 0usize;
        for _ in 0..n_sub {
            let clear = (r.u8() % 64) as u16;
            let mut prot = (r.u16() % 512) as u32;
            if align16 {
                prot &= !15;
            }
            if clear == 0 && prot == 0 {
                continue;
            }
            total += clear as usize + prot as usize;
            list.push(SubsampleEntry {
                bytes_of_clear_data: clear,
                bytes_of_protected_data: prot,
            });
        }
        if list.is_empty() {
            return;
        }
        // §9.5.1: Σ(clear+protected) must equal the sample length.
        data = r.take(total);
        data.resize(total, 0xa5);
        subsamples = Some(list);
    } else {
        data = r.take(payload_len);
        data.resize(payload_len, 0xa5);
    }

    // ── Arm 1: encrypt∘decrypt identity ────────────────────────────
    let plaintext = data.clone();
    let enc = cenc_cipher::encrypt_sample_in_place(
        &decision,
        &key,
        per_sample_iv.as_deref(),
        subsamples.as_deref(),
        &mut data,
    );
    match enc {
        Ok(()) => {
            cenc_cipher::decrypt_sample_in_place(
                &decision,
                &key,
                per_sample_iv.as_deref(),
                subsamples.as_deref(),
                &mut data,
            )
            .expect("decrypt must accept what encrypt accepted");
            assert_eq!(data, plaintext, "CENC encrypt∘decrypt identity");
        }
        Err(_) => {
            // Rejected structurally (e.g. §9.4.3 / §10.2 partial CBC
            // block) — the buffer must be usable either way; nothing
            // further to assert.
        }
    }

    // ── Arm 2: hostile plan walking ────────────────────────────────
    // Full-range subsample fields exercise the `checked_add` overflow
    // guards and the `row_end > sample_len` bound check (which rejects
    // an over-long protected run before any step is emitted). The
    // *sample_len* is kept modest, though: for a pattern scheme the
    // returned plan is legitimately O(protected_len / pattern) steps,
    // so a truthful backing length is what bounds the allocation — in
    // the real pipeline `decrypt_sample_in_place` passes `data.len()`,
    // never an unbacked size. Feeding a multi-GiB sample_len here would
    // ask the planner to emit a valid (but enormous) plan for bytes
    // that do not exist, which is a harness artefact, not a parser bug.
    let n_hostile = (r.u8() % 5) as usize;
    let hostile: Vec<SubsampleEntry> = (0..n_hostile)
        .map(|_| SubsampleEntry {
            bytes_of_clear_data: r.u16(),
            bytes_of_protected_data: r.u32(),
        })
        .collect();
    let hostile_len = (r.u16() as u64).wrapping_add(r.u8() as u64);
    let _ = cenc::plan_sample_cipher(
        &decision,
        if hostile.is_empty() {
            None
        } else {
            Some(&hostile)
        },
        hostile_len,
    );

    // ── Arm 3: hostile senc/seig parsing + decision routing ────────
    let iv_pick = [0u8, 8, 16][(r.u8() % 3) as usize];
    let rest = r.rest();
    let _ = cenc::parse_senc(rest, iv_pick);
    let _ = cenc::parse_seig(rest);
    if rest.len() >= 20 {
        // Arbitrary scheme FourCC × arbitrary tenc bytes: the decision
        // constructor must accept or reject structurally, never panic.
        let mut four = [0u8; 4];
        four.copy_from_slice(&rest[0..4]);
        if let Ok(t) = cenc::parse_tenc(&rest[4..]) {
            let _ = CencSchemeDecision::new(CencScheme::from_fourcc(&four), t);
        }
    }
});
