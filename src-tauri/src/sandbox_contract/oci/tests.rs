//! Acceptance tests for V10: every VM-W33 acceptance item (malicious archive paths,
//! links, metadata, decompression bombs, corrupt layers, cache permission boundaries, no
//! host execution of hooks or entrypoints) and the importer parts of VM-P37 and VM-CP-30
//! (archive bomb, unsafe path, corrupt layer, forged provenance), on in-memory fixtures.

use super::fixtures::*;
use super::*;
use crate::foundation::catalog::{ArtifactClass, ObjectStatus, Scope};
use crate::foundation::ids::Clock;
use crate::sandbox_contract::files::{
    ImageArchiveRefusal as ArchiveRefusal, ImageName, InspectionMethod, NameRefusal,
};

fn guest(text: &str) -> ImageName {
    ImageName::parse(text).unwrap()
}

fn read(tar: &[u8], codec: LayerCodec) -> Result<LayerReport, LayerRefusal> {
    read_with(tar, codec, &ImportLimits::default())
}

fn read_with(
    tar: &[u8],
    codec: LayerCodec,
    limits: &ImportLimits,
) -> Result<LayerReport, LayerRefusal> {
    let (blob, diff_id) = layer(tar, codec);
    read_layer(&blob, &diff_id, limits, &mut ImageBudget::new(limits))
}

fn unsafe_name(index: usize, refusal: NameRefusal) -> LayerRefusal {
    LayerRefusal::Archive {
        refusal: ArchiveRefusal::UnsafeName { index, refusal },
    }
}

fn tar_refusal(result: Result<LayerReport, LayerRefusal>) -> TarRefusal {
    match result {
        Err(LayerRefusal::Tar { refusal }) => refusal,
        other => panic!("expected a tar refusal, got {other:?}"),
    }
}

fn stream_refusal(result: Result<LayerReport, LayerRefusal>) -> StreamRefusal {
    match result {
        Err(LayerRefusal::Stream { refusal }) => refusal,
        other => panic!("expected a stream refusal, got {other:?}"),
    }
}

const CODECS: [LayerCodec; 3] = [LayerCodec::Uncompressed, LayerCodec::Gzip, LayerCodec::Zstd];

mod vm_boundary {
    use super::*;

    #[test]
    fn the_vm_tree_matches_the_reference_including_an_ordinary_sticky_tmp_directory() {
        let mut harness = Harness::new();
        let mut fx = image(&[(
            tar_of(&[
                Fx::Dir {
                    name: "tmp".into(),
                    mode: 0o1777,
                },
                file("tmp/message", b"hello"),
            ]),
            LayerCodec::Gzip,
        )]);
        let request = harness.request(&fx, tenant("a"));
        let prepared = harness
            .importer
            .prepare(&harness.catalog, &mut fx.blobs, &request)
            .unwrap();
        let reference = harness.importer.read_in_process(&prepared).unwrap();
        // Shared with the Go importer test; both compute this tree independently.
        let encoded = reference.tree().body_bytes().unwrap();
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            include_str!(
                "../../../../appliance/agent/cmd/yougori-sandbox-agent/testdata/oci-tree-v1.json"
            )
            .trim_end()
        );
        let read = harness
            .importer
            .tree_from_body(
                &prepared,
                &reference.tree().body_bytes().unwrap(),
                reference.expanded_bytes().to_vec(),
            )
            .unwrap();
        assert_eq!(read, reference);
        let published = harness
            .importer
            .publish_read(&mut harness.catalog, &request, prepared, read)
            .unwrap();
        assert_eq!(published.layers.len(), 1);
        assert!(harness.catalog.quota_usage(&tenant("a")).published_bytes > 0);
    }

    #[test]
    fn vm_reports_cannot_name_bytes_past_the_layer_or_privileged_mode_bits() {
        let harness = Harness::new();
        let mut fx = image(&[(tar_of(&[file("payload", b"hello")]), LayerCodec::Gzip)]);
        let request = harness.request(&fx, tenant("a"));
        let prepared = harness
            .importer
            .prepare(&harness.catalog, &mut fx.blobs, &request)
            .unwrap();
        let reference = harness.importer.read_in_process(&prepared).unwrap();
        let body = reference.tree().body_bytes().unwrap();
        let report = |bytes: &[u8], sizes: Vec<u64>| {
            harness.importer.tree_from_body(&prepared, bytes, sizes)
        };
        let mut forged: serde_json::Value = serde_json::from_slice(&body).unwrap();
        forged["entries"][0]["node"]["content"]["data_offset_bytes"] = serde_json::json!(u64::MAX);
        assert!(report(
            &serde_json::to_vec(&forged).unwrap(),
            reference.expanded_bytes().to_vec()
        )
        .is_err());
        for mode in [0o4755, 0o2755, 0x10000] {
            let mut forged: serde_json::Value = serde_json::from_slice(&body).unwrap();
            forged["entries"][0]["node"]["mode"] = serde_json::json!(mode);
            assert!(report(
                &serde_json::to_vec(&forged).unwrap(),
                reference.expanded_bytes().to_vec()
            )
            .is_err());
        }
        assert!(report(&body, vec![]).is_err());
        assert!(report(&body, vec![1]).is_err());
        assert!(report(&body, vec![u64::MAX]).is_err());
    }

    #[test]
    fn a_parsed_tree_is_bound_to_the_prepared_manifest_and_original_request() {
        let mut harness = Harness::new();
        let mut first = image(&[(tar_of(&[file("payload", b"first")]), LayerCodec::Gzip)]);
        let mut second = image(&[(tar_of(&[file("payload", b"second")]), LayerCodec::Gzip)]);
        let request = harness.request(&first, tenant("a"));
        let prepared = harness
            .importer
            .prepare(&harness.catalog, &mut first.blobs, &request)
            .unwrap();
        let read = harness.importer.read_in_process(&prepared).unwrap();
        let other = harness.request(&second, tenant("a"));
        let prepared_other = harness
            .importer
            .prepare(&harness.catalog, &mut second.blobs, &other)
            .unwrap();
        assert!(harness
            .importer
            .publish_read(&mut harness.catalog, &other, prepared_other, read)
            .is_err());
        let read = harness.importer.read_in_process(&prepared).unwrap();
        let mut changed = request.clone();
        changed.scope = tenant("b");
        assert!(harness
            .importer
            .publish_read(&mut harness.catalog, &changed, prepared, read)
            .is_err());
        assert_eq!(harness.catalog.quota_usage(&tenant("a")).published_bytes, 0);
        assert_eq!(harness.catalog.quota_usage(&tenant("b")).published_bytes, 0);
    }
}

mod layers {
    use super::*;

    #[test]
    fn an_ordinary_layer_reads_the_same_in_every_codec() {
        let tar = tar_of(&[
            dir("etc"),
            file("etc/hostname", b"sandbox\n"),
            symlink("etc/name", "hostname"),
            hardlink("etc/copy", "etc/hostname"),
            Fx::Dir {
                name: "tmp".into(),
                mode: 0o1777,
            },
        ]);
        for codec in CODECS {
            let report = read(&tar, codec).unwrap();
            assert_eq!(report.diff_id, OciDigest::of(&tar));
            assert_eq!(report.expanded_bytes, tar.len() as u64);
            assert_eq!(report.entries.len(), 5);
            let file = &report.entries[1];
            assert_eq!(file.name, guest("etc/hostname"));
            match &file.kind {
                LayerEntryKind::File {
                    size_bytes,
                    sha256,
                    data_offset_bytes,
                } => {
                    assert_eq!(*size_bytes, 8);
                    assert_eq!(*sha256, OciDigest::of(b"sandbox\n"));
                    let start = *data_offset_bytes as usize;
                    assert_eq!(&tar[start..start + 8], b"sandbox\n");
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(
                report.entries[2].kind,
                LayerEntryKind::Symlink {
                    target: "hostname".into()
                }
            );
            assert_eq!(
                report.entries[3].kind,
                LayerEntryKind::HardLink {
                    target: guest("etc/hostname")
                }
            );
            // The sticky bit is neither setuid nor setgid.
            assert_eq!(report.entries[4].mode, 0o1777);
        }
    }

    #[test]
    fn malicious_archive_paths_are_refused_through_v05() {
        // VM-W33 paths and the VM-CP-15 name corpus as tar entries: traversal, absolute,
        // drive, UNC and device paths, alternate data streams, reserved names, Unicode
        // normalization (non-ASCII), dot components, short names and long paths.
        let long = "d/".repeat(600) + "f";
        for (name, refusal) in [
            ("../evil", NameRefusal::Traversal { index: 0 }),
            ("a/../../evil", NameRefusal::Traversal { index: 1 }),
            ("/etc/passwd", NameRefusal::AbsolutePath),
            ("//server/share/x", NameRefusal::AbsolutePath),
            ("//?/C:/x", NameRefusal::AbsolutePath),
            ("a\\..\\b", NameRefusal::Backslash { byte_offset: 1 }),
            ("./etc", NameRefusal::DotComponent { index: 0 }),
            ("a//b", NameRefusal::EmptyComponent { index: 1 }),
        ] {
            let tar = raw_tar(&[raw_file(name, b"x")]);
            assert_eq!(
                read(&tar, LayerCodec::Gzip),
                Err(unsafe_name(0, refusal)),
                "{name}"
            );
        }
        // A long path through a PAX record is still checked by V05; a GNU long name past
        // the V05 bound is refused before it is buffered.
        let pax_long = tar_of(&[pax(&[("path", long.as_bytes())]), file("short", b"x")]);
        assert_eq!(
            read(&pax_long, LayerCodec::Uncompressed),
            Err(unsafe_name(
                0,
                NameRefusal::NameTooLong {
                    bytes: long.len(),
                    limit: 1024
                }
            ))
        );
        let gnu_long = tar_of(&[file(&long, b"x")]);
        assert!(matches!(
            tar_refusal(read(&gnu_long, LayerCodec::Uncompressed)),
            TarRefusal::MetadataTooLarge {
                limit_bytes: 1025,
                ..
            }
        ));
        let pax_path = tar_of(&[
            pax(&[("path", b"../../etc/shadow")]),
            file("innocent", b"x"),
        ]);
        assert_eq!(
            read(&pax_path, LayerCodec::Uncompressed),
            Err(unsafe_name(0, NameRefusal::Traversal { index: 0 }))
        );
        // Linux image trees distinguish case; the host-file suite retains its
        // case-alias refusal. Neither spelling is ever opened on the host.
        let alias = tar_of(&[file("Doc/a", b"1"), file("doc/b", b"2")]);
        assert!(read(&alias, LayerCodec::Uncompressed).is_ok());
    }

    #[test]
    fn malicious_links_are_refused_through_v05() {
        let escaping = [
            raw_link("link", b'2', "../../etc"),
            raw_link("link", b'2', "//etc/passwd"),
        ];
        for entry in escaping {
            assert_eq!(
                read(&raw_tar(&[entry]), LayerCodec::Gzip),
                Err(LayerRefusal::Archive {
                    refusal: ArchiveRefusal::EscapingLink {
                        index: 0,
                        name: guest("link")
                    }
                })
            );
        }
        // A link to a directory, then a file written through it.
        let through = tar_of(&[symlink("up", "elsewhere"), file("up/passwd", b"x")]);
        assert!(matches!(
            read(&through, LayerCodec::Uncompressed),
            Err(LayerRefusal::Archive {
                refusal: ArchiveRefusal::Collision { index: 1, .. }
            })
        ));
        let chain = tar_of(&[symlink("a", "b"), symlink("b", "a")]);
        assert!(matches!(
            read(&chain, LayerCodec::Uncompressed),
            Err(LayerRefusal::Archive {
                refusal: ArchiveRefusal::EscapingLink { .. }
            })
        ));
        // Hard links only to an earlier regular file of the same layer.
        for target in ["../../etc/shadow", "/etc/shadow", "later", "dir"] {
            let tar = raw_tar(&[
                raw("dir/", b'5', b""),
                raw_link("h", b'1', target),
                raw_file("later", b"x"),
            ]);
            assert_eq!(
                read(&tar, LayerCodec::Uncompressed),
                Err(LayerRefusal::Archive {
                    refusal: ArchiveRefusal::HardLinkTarget {
                        index: 1,
                        name: guest("h")
                    }
                }),
                "{target}"
            );
        }
    }

    #[test]
    fn devices_fifos_and_other_entry_types_are_refused() {
        for entry in [
            Fx::CharDevice {
                name: "dev/null".into(),
            },
            Fx::BlockDevice {
                name: "dev/sda".into(),
            },
            Fx::Fifo {
                name: "run/pipe".into(),
            },
        ] {
            let name = match &entry {
                Fx::CharDevice { name } | Fx::BlockDevice { name } | Fx::Fifo { name } => {
                    guest(name)
                }
                _ => unreachable!(),
            };
            assert_eq!(
                read(&tar_of(&[entry]), LayerCodec::Gzip),
                Err(LayerRefusal::Archive {
                    refusal: ArchiveRefusal::DeviceEntry { index: 0, name }
                })
            );
        }
        // Sockets cannot be written in tar; contiguous files, sparse files, global PAX
        // headers and volume labels are refused by type.
        for flag in [b'7', b'S', b'g', b'V', b'D', b'M', b'Z'] {
            let tar = raw_tar(&[raw("x", flag, b"")]);
            assert_eq!(
                tar_refusal(read(&tar, LayerCodec::Uncompressed)),
                TarRefusal::UnsupportedEntryType {
                    offset_bytes: 0,
                    flag
                }
            );
        }
    }

    #[test]
    fn setuid_and_setgid_bits_are_refused_not_stripped() {
        for mode in [0o4755, 0o2755, 0o6755] {
            let tar = tar_of(&[file_mode("usr/bin/su", b"x", mode)]);
            assert_eq!(
                read(&tar, LayerCodec::Zstd),
                Err(LayerRefusal::SetuidOrSetgid {
                    index: 0,
                    name: guest("usr/bin/su"),
                    mode
                })
            );
        }
        let tar = tar_of(&[file_mode("usr/bin/tool", b"x", 0o755)]);
        assert_eq!(read(&tar, LayerCodec::Zstd).unwrap().entries[0].mode, 0o755);
    }

    #[test]
    fn mode_fields_must_be_permissions_or_their_own_type_bits() {
        let mut typed = raw_file("f", b"x");
        typed.mode_field = b"0100644\0".to_vec();
        assert_eq!(
            read(&raw_tar(&[typed]), LayerCodec::Uncompressed)
                .unwrap()
                .entries[0]
                .mode,
            0o644
        );
        let mut directory_bits = raw_file("f", b"x");
        directory_bits.mode_field = b"0040644\0".to_vec();
        assert_eq!(
            tar_refusal(read(&raw_tar(&[directory_bits]), LayerCodec::Uncompressed)),
            TarRefusal::MalformedField {
                offset_bytes: 0,
                field: "mode"
            }
        );
        let mut garbage = raw_file("f", b"x");
        garbage.mode_field = b"rwxr-x-\0".to_vec();
        assert_eq!(
            tar_refusal(read(&raw_tar(&[garbage]), LayerCodec::Uncompressed)),
            TarRefusal::MalformedField {
                offset_bytes: 0,
                field: "mode"
            }
        );
    }
}

mod metadata {
    use super::*;

    fn read_pax(records: &[(&str, &[u8])]) -> Result<LayerReport, LayerRefusal> {
        read(
            &tar_of(&[pax(records), file("f", b"x")]),
            LayerCodec::Uncompressed,
        )
    }

    #[test]
    fn pax_records_are_applied_when_allowlisted() {
        let report = read_pax(&[
            ("path", b"renamed/by/pax"),
            ("mtime", b"1700000000.5"),
            ("uid", b"1000"),
            ("gid", b"1001"),
            ("uname", b"app"),
            ("SCHILY.xattr.user.comment", b"\x00\x01binary"),
        ])
        .unwrap();
        let entry = &report.entries[0];
        assert_eq!(entry.name, guest("renamed/by/pax"));
        assert_eq!((entry.uid, entry.gid), (1000, 1001));
        assert_eq!(entry.xattrs.get("user.comment").unwrap(), b"\x00\x01binary");
    }

    #[test]
    fn privileged_and_unknown_records_are_refused() {
        for name in [
            "security.capability",
            "trusted.overlay.opaque",
            "system.posix_acl_access",
            "security.selinux",
            "user.",
        ] {
            let key = format!("SCHILY.xattr.{name}");
            assert_eq!(
                tar_refusal(read_pax(&[(&key, b"v")])),
                TarRefusal::XattrNotAllowed {
                    offset_bytes: 0,
                    name: name.into()
                },
                "{name}"
            );
        }
        for key in [
            "LIBARCHIVE.xattr.user.x",
            "GNU.sparse.size",
            "comment",
            "hdrcharset",
        ] {
            assert_eq!(
                tar_refusal(read_pax(&[(key, b"v")])),
                TarRefusal::PaxKeyNotAllowed {
                    offset_bytes: 0,
                    key: key.into()
                }
            );
        }
        assert_eq!(
            tar_refusal(read_pax(&[("mtime", b"-1")])),
            TarRefusal::PaxMalformed { offset_bytes: 0 }
        );
        assert_eq!(
            tar_refusal(read_pax(&[("size", b"12x")])),
            TarRefusal::PaxMalformed { offset_bytes: 0 }
        );
    }

    #[test]
    fn pax_headers_are_bounded() {
        let limits = ImportLimits {
            max_pax_bytes: 256,
            max_pax_records: 3,
            max_xattrs_per_entry: 2,
            max_xattr_value_bytes: 8,
            ..ImportLimits::default()
        };
        let read_limited = |records: &[(&str, &[u8])]| {
            read_with(
                &tar_of(&[pax(records), file("f", b"x")]),
                LayerCodec::Uncompressed,
                &limits,
            )
        };
        let big = vec![b'a'; 300];
        assert!(matches!(
            tar_refusal(read_limited(&[("SCHILY.xattr.user.big", &big)])),
            TarRefusal::MetadataTooLarge {
                limit_bytes: 256,
                ..
            }
        ));
        assert_eq!(
            tar_refusal(read_limited(&[
                ("uid", b"1"),
                ("gid", b"1"),
                ("uname", b"a"),
                ("gname", b"b")
            ])),
            TarRefusal::PaxTooManyRecords {
                offset_bytes: 0,
                limit: 3
            }
        );
        assert_eq!(
            tar_refusal(read_limited(&[
                ("SCHILY.xattr.user.a", b"1"),
                ("SCHILY.xattr.user.b", b"2"),
                ("SCHILY.xattr.user.c", b"3")
            ])),
            TarRefusal::TooManyXattrs {
                offset_bytes: 0,
                limit: 2
            }
        );
        assert_eq!(
            tar_refusal(read_limited(&[("SCHILY.xattr.user.a", b"123456789")])),
            TarRefusal::XattrTooLarge {
                offset_bytes: 0,
                bytes: 9,
                limit: 8
            }
        );
        assert_eq!(
            tar_refusal(read_limited(&[("uid", b"1"), ("uid", b"2")])),
            TarRefusal::PaxDuplicateKey {
                offset_bytes: 0,
                key: "uid".into()
            }
        );
    }

    #[test]
    fn malformed_and_dangling_extended_headers_are_refused() {
        let bad_length = raw_tar(&[
            raw("PaxHeaders/x", b'x', b"99 path=a\n"),
            raw_file("f", b"x"),
        ]);
        assert_eq!(
            tar_refusal(read(&bad_length, LayerCodec::Uncompressed)),
            TarRefusal::PaxMalformed { offset_bytes: 0 }
        );
        let leading_zero = raw_tar(&[
            raw("PaxHeaders/x", b'x', b"011 path=a\n"),
            raw_file("f", b"x"),
        ]);
        assert_eq!(
            tar_refusal(read(&leading_zero, LayerCodec::Uncompressed)),
            TarRefusal::PaxMalformed { offset_bytes: 0 }
        );
        let twice = tar_of(&[
            pax(&[("uid", b"1")]),
            pax(&[("gid", b"1")]),
            file("f", b"x"),
        ]);
        assert_eq!(
            tar_refusal(read(&twice, LayerCodec::Uncompressed)),
            TarRefusal::DanglingMetadata { offset_bytes: 1024 }
        );
        let at_end = tar_of(&[file("f", b"x"), pax(&[("uid", b"1")])]);
        assert_eq!(
            tar_refusal(read(&at_end, LayerCodec::Uncompressed)),
            TarRefusal::DanglingMetadata { offset_bytes: 1024 }
        );
        let long = format!("{}\0", "n".repeat(200));
        let both = raw_tar(&[
            raw(
                "PaxHeaders/x",
                b'x',
                &pax_bytes(&[("path".into(), b"p".to_vec())]),
            ),
            raw("././@LongLink", b'L', long.as_bytes()),
            raw_file("f", b"x"),
        ]);
        assert_eq!(
            tar_refusal(read(&both, LayerCodec::Uncompressed)),
            TarRefusal::ConflictingNames { offset_bytes: 2048 }
        );
        let huge_long_name = raw_tar(&[
            raw("././@LongLink", b'L', &vec![b'a'; 2000]),
            raw_file("f", b"x"),
        ]);
        assert!(matches!(
            tar_refusal(read(&huge_long_name, LayerCodec::Uncompressed)),
            TarRefusal::MetadataTooLarge {
                limit_bytes: 1025,
                ..
            }
        ));
        let mut linked_file = raw_file("f", b"x");
        linked_file.link = b"elsewhere".to_vec();
        assert_eq!(
            tar_refusal(read(&raw_tar(&[linked_file]), LayerCodec::Uncompressed)),
            TarRefusal::MalformedField {
                offset_bytes: 0,
                field: "linkname"
            }
        );
    }

    #[test]
    fn a_pax_size_is_held_to_the_single_file_limit_before_data_is_read() {
        let tar = tar_of(&[pax(&[("size", b"99999999999999")]), file("f", b"")]);
        assert_eq!(
            read(&tar, LayerCodec::Uncompressed),
            Err(LayerRefusal::Archive {
                refusal: ArchiveRefusal::EntryTooLarge {
                    index: 0,
                    uncompressed_bytes: 99_999_999_999_999,
                    limit: ImportLimits::default().max_file_bytes
                }
            })
        );
    }
}

mod corrupt {
    use super::*;

    #[test]
    fn corrupt_tar_framing_is_refused_with_typed_reasons() {
        let mut bad = raw_file("f", b"x");
        bad.break_checksum = true;
        assert!(matches!(
            tar_refusal(read(&raw_tar(&[bad]), LayerCodec::Uncompressed)),
            TarRefusal::BadChecksum {
                offset_bytes: 0,
                ..
            }
        ));
        let good = raw_tar(&[raw_file("f", b"hello")]);
        for cut in [100, 512, 515, 1024, good.len() - 1] {
            assert!(matches!(
                tar_refusal(read(&good[..cut], LayerCodec::Uncompressed)),
                TarRefusal::Truncated { .. }
            ));
        }
        let mut trailing = good.clone();
        trailing.extend_from_slice(b"garbage");
        assert_eq!(
            tar_refusal(read(&trailing, LayerCodec::Uncompressed)),
            TarRefusal::TrailingGarbage {
                offset_bytes: good.len() as u64
            }
        );
        // Zero padding after the end blocks is part of the stream and accepted.
        let mut padded = good.clone();
        padded.extend_from_slice(&[0u8; 8192]);
        assert!(read(&padded, LayerCodec::Uncompressed).is_ok());
        let mut dirty_padding = good.clone();
        dirty_padding[512 + 5] = b'!';
        assert_eq!(
            tar_refusal(read(&dirty_padding, LayerCodec::Uncompressed)),
            TarRefusal::NonZeroPadding { offset_bytes: 517 }
        );
        let mut lone_zero = raw_entry(&raw_file("a", b""));
        lone_zero.extend_from_slice(&[0u8; 512]);
        lone_zero.extend_from_slice(&raw_tar(&[raw_file("b", b"")]));
        assert_eq!(
            tar_refusal(read(&lone_zero, LayerCodec::Uncompressed)),
            TarRefusal::MalformedEnd { offset_bytes: 512 }
        );
        let mut v7 = raw_file("f", b"x");
        v7.magic = [0; 8];
        assert_eq!(
            tar_refusal(read(&raw_tar(&[v7]), LayerCodec::Uncompressed)),
            TarRefusal::UnsupportedFormat { offset_bytes: 0 }
        );
        let mut gnu = raw_file("f", b"x");
        gnu.magic = GNU_MAGIC;
        assert!(read(&raw_tar(&[gnu]), LayerCodec::Uncompressed).is_ok());
        let mut data_on_link = raw_link("l", b'2', "f");
        data_on_link.data = b"hidden".to_vec();
        assert_eq!(
            tar_refusal(read(
                &raw_tar(&[raw_file("f", b""), data_on_link]),
                LayerCodec::Uncompressed
            )),
            TarRefusal::DataOnNonFile {
                offset_bytes: 512,
                size_bytes: 6
            }
        );
        let non_utf8 = raw_tar(&[Raw {
            name: vec![b'a', 0xff],
            ..raw_file("x", b"")
        }]);
        assert_eq!(
            tar_refusal(read(&non_utf8, LayerCodec::Uncompressed)),
            TarRefusal::NonUtf8 {
                offset_bytes: 0,
                field: "name"
            }
        );
    }

    #[test]
    fn a_huge_declared_size_is_refused_before_any_data_is_read() {
        let mut huge = raw_file("big", b"");
        huge.size_field = Some(b"77777777777\0".to_vec());
        let tar = [raw_header(&huge).to_vec(), vec![0u8; 1024]].concat();
        let limits = ImportLimits {
            max_file_bytes: 1 << 30,
            ..ImportLimits::default()
        };
        assert_eq!(
            read_with(&tar, LayerCodec::Gzip, &limits),
            Err(LayerRefusal::Archive {
                refusal: ArchiveRefusal::EntryTooLarge {
                    index: 0,
                    uncompressed_bytes: 0o77777777777,
                    limit: 1 << 30
                }
            })
        );
        // GNU base-256: 2^40 bytes declared in a 12-byte field.
        let mut base256 = raw_file("big", b"");
        let mut field = vec![0x80u8];
        field.extend_from_slice(&[0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0]);
        base256.size_field = Some(field);
        let tar = [raw_header(&base256).to_vec(), vec![0u8; 1024]].concat();
        assert!(matches!(
            read(&tar, LayerCodec::Uncompressed),
            Err(LayerRefusal::Archive {
                refusal: ArchiveRefusal::EntryTooLarge { .. }
            })
        ));
        let mut negative = raw_file("big", b"");
        negative.size_field = Some(vec![0xff; 12]);
        assert_eq!(
            tar_refusal(read(&raw_tar(&[negative]), LayerCodec::Uncompressed)),
            TarRefusal::MalformedField {
                offset_bytes: 0,
                field: "size"
            }
        );
    }

    #[test]
    fn corrupt_compressed_streams_are_refused_with_typed_reasons() {
        // Incompressible bytes, so a truncated stream ends before any ratio limit.
        let tar = tar_of(&[file("f", &seeded_bytes(20_000, 7))]);
        let diff_id = OciDigest::of(&tar);
        let limits = ImportLimits::default();
        let check = |bytes: Vec<u8>, media_type: MediaType| {
            read_layer(
                &verified(bytes, media_type),
                &diff_id,
                &limits,
                &mut ImageBudget::new(&limits),
            )
        };
        let gz = gzip(&tar);
        assert_eq!(
            stream_refusal(check(gz[..gz.len() - 4].to_vec(), MediaType::LayerTarGzip)),
            StreamRefusal::Truncated {
                codec: LayerCodec::Gzip
            }
        );
        assert_eq!(
            stream_refusal(check(gz[..gz.len() / 2].to_vec(), MediaType::LayerTarGzip)),
            StreamRefusal::Truncated {
                codec: LayerCodec::Gzip
            }
        );
        let mut crc = gz.clone();
        let at = crc.len() - 6;
        crc[at] ^= 0xff;
        assert!(matches!(
            stream_refusal(check(crc, MediaType::LayerTarGzip)),
            StreamRefusal::Corrupt {
                codec: LayerCodec::Gzip,
                ..
            }
        ));
        let mut trailing = gz.clone();
        trailing.extend_from_slice(b"TRAILING");
        assert_eq!(
            stream_refusal(check(trailing, MediaType::LayerTarGzip)),
            StreamRefusal::TrailingData {
                codec: LayerCodec::Gzip,
                trailing_bytes: 8
            }
        );
        let mut two_members = gz.clone();
        two_members.extend_from_slice(&gzip(b"more"));
        assert!(matches!(
            stream_refusal(check(two_members, MediaType::LayerTarGzip)),
            StreamRefusal::TrailingData {
                codec: LayerCodec::Gzip,
                ..
            }
        ));
        let zs = zstd(&tar);
        assert_eq!(
            stream_refusal(check(zs[..zs.len() - 1].to_vec(), MediaType::LayerTarZstd)),
            StreamRefusal::Truncated {
                codec: LayerCodec::Zstd
            }
        );
        let mut two_frames = zs.clone();
        two_frames.extend_from_slice(&zstd(b"second frame"));
        assert!(matches!(
            stream_refusal(check(two_frames, MediaType::LayerTarZstd)),
            StreamRefusal::TrailingData {
                codec: LayerCodec::Zstd,
                ..
            }
        ));
        assert!(matches!(
            stream_refusal(check(b"not zstd at all".to_vec(), MediaType::LayerTarZstd)),
            StreamRefusal::Corrupt {
                codec: LayerCodec::Zstd,
                ..
            }
        ));
    }

    #[test]
    fn the_media_type_decides_the_codec_and_nothing_is_sniffed() {
        let tar = tar_of(&[file("f", b"x")]);
        let diff_id = OciDigest::of(&tar);
        let limits = ImportLimits::default();
        let check = |bytes: Vec<u8>, media_type: MediaType| {
            read_layer(
                &verified(bytes, media_type),
                &diff_id,
                &limits,
                &mut ImageBudget::new(&limits),
            )
        };
        // gzip bytes declared as plain tar are read as tar, and fail as tar.
        assert!(matches!(
            check(gzip(&tar), MediaType::LayerTar),
            Err(LayerRefusal::Tar { .. })
        ));
        // Plain tar declared as gzip or zstd fails in the declared decoder.
        assert!(matches!(
            stream_refusal(check(tar.clone(), MediaType::LayerTarGzip)),
            StreamRefusal::Corrupt {
                codec: LayerCodec::Gzip,
                ..
            }
        ));
        assert!(matches!(
            stream_refusal(check(zstd(&tar), MediaType::LayerTarGzip)),
            StreamRefusal::Corrupt {
                codec: LayerCodec::Gzip,
                ..
            }
        ));
        assert!(matches!(
            stream_refusal(check(gzip(&tar), MediaType::LayerTarZstd)),
            StreamRefusal::Corrupt {
                codec: LayerCodec::Zstd,
                ..
            }
        ));
        assert_eq!(
            stream_refusal(check(b"{}".to_vec(), MediaType::ImageConfig)),
            StreamRefusal::NotALayer {
                media_type: MediaType::ImageConfig
            }
        );
    }

    #[test]
    fn the_expanded_stream_must_match_the_diff_id() {
        let tar = tar_of(&[file("f", b"x")]);
        let (blob, _) = layer(&tar, LayerCodec::Gzip);
        let other = OciDigest::of(b"another layer");
        let limits = ImportLimits::default();
        assert_eq!(
            stream_refusal(read_layer(
                &blob,
                &other,
                &limits,
                &mut ImageBudget::new(&limits)
            )),
            StreamRefusal::DiffIdMismatch {
                declared: other,
                found: OciDigest::of(&tar)
            }
        );
    }
}

mod bombs {
    use super::*;

    fn zeros_tar(bytes: usize) -> Vec<u8> {
        tar_of(&[file("zeros", &vec![0u8; bytes])])
    }

    #[test]
    fn a_layer_bomb_stops_one_byte_past_the_expanded_limit() {
        let tar = zeros_tar(8 << 20);
        for codec in [LayerCodec::Gzip, LayerCodec::Zstd] {
            let limits = ImportLimits {
                max_layer_expanded_bytes: 1 << 20,
                max_ratio: 1_000_000,
                ..ImportLimits::default()
            };
            assert_eq!(
                stream_refusal(read_with(&tar, codec, &limits)),
                StreamRefusal::ExpandedTooLarge {
                    expanded_bytes: (1 << 20) + 1,
                    limit_bytes: 1 << 20
                }
            );
        }
    }

    #[test]
    fn a_ratio_bomb_stops_at_the_ratio_of_the_compressed_blob() {
        let tar = zeros_tar(8 << 20);
        for codec in [LayerCodec::Gzip, LayerCodec::Zstd] {
            let (blob, diff_id) = layer(&tar, codec);
            let compressed = blob.bytes().len() as u64;
            let limits = ImportLimits::default();
            assert!(compressed * limits.max_ratio < tar.len() as u64);
            assert_eq!(
                stream_refusal(read_layer(
                    &blob,
                    &diff_id,
                    &limits,
                    &mut ImageBudget::new(&limits)
                )),
                StreamRefusal::RatioExceeded {
                    expanded_bytes: compressed * limits.max_ratio + 1,
                    compressed_bytes: compressed,
                    max_ratio: limits.max_ratio
                }
            );
        }
    }

    #[test]
    fn the_expanded_limit_is_inclusive() {
        let tar = tar_of(&[file("f", &vec![b'q'; 3000])]);
        let exact = ImportLimits {
            max_layer_expanded_bytes: tar.len() as u64,
            ..ImportLimits::default()
        };
        assert_eq!(
            read_with(&tar, LayerCodec::Gzip, &exact)
                .unwrap()
                .expanded_bytes,
            tar.len() as u64
        );
        let short = ImportLimits {
            max_layer_expanded_bytes: tar.len() as u64 - 1,
            ..ImportLimits::default()
        };
        assert_eq!(
            stream_refusal(read_with(&tar, LayerCodec::Gzip, &short)),
            StreamRefusal::ExpandedTooLarge {
                expanded_bytes: tar.len() as u64,
                limit_bytes: tar.len() as u64 - 1
            }
        );
        // A stored layer expands exactly 1x, which a ratio of 1 accepts.
        let one = ImportLimits {
            max_ratio: 1,
            ..ImportLimits::default()
        };
        assert!(read_with(&tar, LayerCodec::Uncompressed, &one).is_ok());
    }

    #[test]
    fn the_image_budget_is_shared_across_layers() {
        let tar = tar_of(&[file("f", &vec![b'q'; 4000])]);
        let limits = ImportLimits {
            max_layer_expanded_bytes: tar.len() as u64,
            max_image_expanded_bytes: tar.len() as u64 * 3 / 2,
            ..ImportLimits::default()
        };
        let mut budget = ImageBudget::new(&limits);
        let (blob, diff_id) = layer(&tar, LayerCodec::Gzip);
        read_layer(&blob, &diff_id, &limits, &mut budget).unwrap();
        assert_eq!(budget.remaining_expanded_bytes, tar.len() as u64 / 2);
        assert_eq!(
            stream_refusal(read_layer(&blob, &diff_id, &limits, &mut budget)),
            StreamRefusal::ImageExpandedTooLarge {
                expanded_bytes: tar.len() as u64 / 2 + 1,
                limit_bytes: tar.len() as u64 / 2
            }
        );
        // A refused layer charges nothing.
        assert_eq!(budget.remaining_expanded_bytes, tar.len() as u64 / 2);
    }

    #[test]
    fn entry_count_and_single_file_size_are_checked_from_headers() {
        let many: Vec<Fx> = (0..50).map(|i| file(&format!("f{i}"), b"")).collect();
        let limits = ImportLimits {
            max_entries_per_layer: 10,
            max_image_entries: 20,
            ..ImportLimits::default()
        };
        assert_eq!(
            read_with(&tar_of(&many), LayerCodec::Gzip, &limits),
            Err(LayerRefusal::TooManyEntries {
                entries: 11,
                limit: 10
            })
        );
        let mut budget = ImageBudget {
            remaining_entries: 4,
            ..ImageBudget::new(&limits)
        };
        let (blob, diff_id) = layer(&tar_of(&many[..6]), LayerCodec::Gzip);
        assert_eq!(
            read_layer(&blob, &diff_id, &limits, &mut budget),
            Err(LayerRefusal::ImageTooManyEntries {
                entries: 5,
                limit: 4
            })
        );
        let small_files = ImportLimits {
            max_file_bytes: 100,
            ..ImportLimits::default()
        };
        assert_eq!(
            read_with(
                &tar_of(&[file("big", &[1u8; 101])]),
                LayerCodec::Zstd,
                &small_files
            ),
            Err(LayerRefusal::Archive {
                refusal: ArchiveRefusal::EntryTooLarge {
                    index: 0,
                    uncompressed_bytes: 101,
                    limit: 100
                }
            })
        );
    }

    #[test]
    fn compressed_size_and_zstd_windows_are_bounded_before_decoding() {
        let tar = zeros_tar(1 << 16);
        let tiny = ImportLimits {
            max_layer_compressed_bytes: 10,
            ..ImportLimits::default()
        };
        assert!(matches!(
            stream_refusal(read_with(&tar, LayerCodec::Gzip, &tiny)),
            StreamRefusal::CompressedTooLarge {
                limit_bytes: 10,
                ..
            }
        ));
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        encoder.window_log(24).unwrap();
        encoder.long_distance_matching(true).unwrap();
        std::io::Write::write_all(&mut encoder, &tar).unwrap();
        let wide = encoder.finish().unwrap();
        let narrow = ImportLimits {
            max_zstd_window_log: 20,
            ..ImportLimits::default()
        };
        let diff_id = OciDigest::of(&tar);
        assert!(matches!(
            stream_refusal(read_layer(
                &verified(wide, MediaType::LayerTarZstd),
                &diff_id,
                &narrow,
                &mut ImageBudget::new(&narrow)
            )),
            StreamRefusal::Corrupt {
                codec: LayerCodec::Zstd,
                ..
            }
        ));
    }
}

mod whiteouts {
    use super::*;

    fn tree_of(layers: &[Vec<Fx>]) -> Result<TreeIndex, String> {
        let limits = ImportLimits::default();
        let mut builder = TreeBuilder::new(&limits);
        for entries in layers {
            let report =
                read(&tar_of(entries), LayerCodec::Uncompressed).map_err(|e| format!("{e:?}"))?;
            builder.apply(&report).map_err(|e| format!("{e:?}"))?;
        }
        builder.finish().map_err(|e| format!("{e:?}"))
    }

    fn names(tree: &TreeIndex) -> Vec<&str> {
        tree.entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect()
    }

    fn tree_refusal(layers: &[Vec<Fx>]) -> TreeRefusal {
        let limits = ImportLimits::default();
        let mut builder = TreeBuilder::new(&limits);
        for entries in layers {
            let report = read(&tar_of(entries), LayerCodec::Uncompressed).unwrap();
            if let Err(refusal) = builder.apply(&report) {
                return refusal;
            }
        }
        builder.finish().unwrap_err()
    }

    #[test]
    fn whiteouts_hide_lower_entries_and_are_hidden_themselves() {
        let tree = tree_of(&[
            vec![
                dir("a"),
                file("a/x", b"1"),
                file("a/y", b"2"),
                dir("b"),
                file("b/z", b"3"),
            ],
            vec![dir("a"), file("a/.wh.x", b""), file(".wh.b", b"")],
        ])
        .unwrap();
        assert_eq!(names(&tree), ["a", "a/y"]);
    }

    #[test]
    fn an_opaque_marker_hides_lower_children_but_keeps_its_own_layer() {
        let tree = tree_of(&[
            vec![
                dir("d"),
                file("d/1", b"1"),
                dir("d/sub"),
                file("d/sub/2", b"2"),
                file("keep", b"k"),
            ],
            vec![dir("d"), file("d/.wh..wh..opq", b""), file("d/3", b"3")],
        ])
        .unwrap();
        assert_eq!(names(&tree), ["d", "d/3", "keep"]);
        let root = tree_of(&[
            vec![file("old", b"o")],
            vec![file(".wh..wh..opq", b""), file("new", b"n")],
        ])
        .unwrap();
        assert_eq!(names(&root), ["new"]);
    }

    #[test]
    fn later_layers_replace_files_and_directories() {
        let tree = tree_of(&[
            vec![file("x", b"file"), dir("d"), file("d/a", b"a")],
            vec![
                dir("x"),
                file("x/y", b"now a dir"),
                file("d", b"now a file"),
            ],
        ])
        .unwrap();
        assert_eq!(names(&tree), ["d", "x", "x/y"]);
        assert!(matches!(tree.get("d"), Some(TreeNode::File { .. })));
        match tree.get("x/y") {
            Some(TreeNode::File { content, .. }) => {
                assert_eq!(content.layer, 1);
                assert_eq!(content.sha256, OciDigest::of(b"now a dir"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(tree.summary.files, 2);
        assert_eq!(tree.summary.directories, 1);
    }

    #[test]
    fn whiteouts_outside_their_directory_or_with_unsafe_names_are_refused() {
        for invalid in ["a/.wh..", "a/.wh..."] {
            assert!(matches!(
                read(
                    &raw_tar(&[raw_file(invalid, b"")]),
                    LayerCodec::Uncompressed
                ),
                Err(LayerRefusal::Whiteout {
                    refusal: WhiteoutRefusal::UnsafeTarget { .. }
                })
            ));
        }
        assert!(read(&tar_of(&[file("a/.wh.CON", b"")]), LayerCodec::Uncompressed).is_ok());
        assert_eq!(
            read(
                &tar_of(&[file("a/.wh..wh.plnk", b"")]),
                LayerCodec::Uncompressed
            ),
            Err(LayerRefusal::Whiteout {
                refusal: WhiteoutRefusal::ReservedName {
                    index: 0,
                    name: guest("a/.wh..wh.plnk")
                }
            })
        );
        assert_eq!(
            read(&tar_of(&[dir("a/.wh.b")]), LayerCodec::Uncompressed),
            Err(LayerRefusal::Whiteout {
                refusal: WhiteoutRefusal::NotRegularFile {
                    index: 0,
                    name: guest("a/.wh.b")
                }
            })
        );
        assert_eq!(
            read(
                &tar_of(&[file("a/.wh.b", b"payload")]),
                LayerCodec::Uncompressed
            ),
            Err(LayerRefusal::Whiteout {
                refusal: WhiteoutRefusal::NotEmpty {
                    index: 0,
                    name: guest("a/.wh.b"),
                    size_bytes: 7
                }
            })
        );
    }

    #[test]
    fn a_whiteout_never_hides_its_own_layer() {
        assert!(read(
            &tar_of(&[file("a/B", b"x"), file("a/.wh.b", b"")]),
            LayerCodec::Uncompressed
        )
        .is_ok());

        for entries in [
            vec![file("a/.wh.b", b""), file("a/b", b"x")],
            vec![file("a/.wh.b", b""), file("a/b/c", b"x")],
        ] {
            assert!(matches!(
                read(&tar_of(&entries), LayerCodec::Uncompressed),
                Err(LayerRefusal::Whiteout {
                    refusal: WhiteoutRefusal::HidesSameLayer { .. }
                })
            ));
        }
    }

    #[test]
    fn links_planted_by_one_layer_cannot_be_used_by_another() {
        assert_eq!(
            tree_refusal(&[
                vec![symlink("lib", "usr/lib")],
                vec![file("lib/evil.so", b"x")]
            ]),
            TreeRefusal::ThroughLink {
                layer: 1,
                index: 0,
                name: guest("lib/evil.so"),
                link: guest("lib")
            }
        );
        assert_eq!(
            tree_refusal(&[
                vec![symlink("lib", "usr/lib")],
                vec![file("lib/.wh.x", b"")]
            ]),
            TreeRefusal::ThroughLink {
                layer: 1,
                index: 0,
                name: guest("lib/x"),
                link: guest("lib")
            }
        );
        // Each layer alone is fine. Contained cross-layer chains now work inside
        // the guest root, but a cross-layer cycle is still refused.
        let tree = tree_of(&[vec![symlink("a", "b")], vec![symlink("b", "c")]]).unwrap();
        assert_eq!(names(&tree), ["a", "b"]);
        assert!(matches!(
            tree_refusal(&[vec![symlink("a", "b")], vec![symlink("b", "a")]]),
            TreeRefusal::Archive {
                refusal: ArchiveRefusal::EscapingLink { .. }
            }
        ));
        assert_eq!(
            tree_refusal(&[vec![file("x", b"file")], vec![file("x/y", b"below a file")]]),
            TreeRefusal::ParentNotDirectory {
                layer: 1,
                index: 0,
                name: guest("x/y"),
                parent: guest("x")
            }
        );
    }

    #[test]
    fn image_names_and_whiteouts_are_case_sensitive_across_layers() {
        let tree = tree_of(&[vec![file("Foo", b"1")], vec![file("foo", b"2")]]).unwrap();
        assert_eq!(names(&tree), ["Foo", "foo"]);
        let tree = tree_of(&[vec![file("foo", b"1")], vec![file(".wh.FOO", b"")]]).unwrap();
        assert_eq!(names(&tree), ["foo"]);
        assert_eq!(
            tree_refusal(&[vec![file("d", b"file")], vec![file("d/.wh..wh..opq", b"")]]),
            TreeRefusal::OpaqueOnNonDirectory {
                layer: 1,
                index: 0,
                directory: guest("d")
            }
        );
    }

    #[test]
    fn hard_links_survive_as_content_when_their_target_goes() {
        let tree = tree_of(&[
            vec![file("bin/a", b"binary"), hardlink("bin/b", "bin/a")],
            vec![dir("bin"), file("bin/.wh.a", b"")],
        ])
        .unwrap();
        match tree.get("bin/b") {
            Some(TreeNode::File {
                content,
                hard_link_to,
                ..
            }) => {
                assert_eq!(*hard_link_to, None);
                assert_eq!(content.sha256, OciDigest::of(b"binary"));
                assert_eq!(content.layer, 0);
            }
            other => panic!("{other:?}"),
        }
        let kept = tree_of(&[vec![file("bin/a", b"binary"), hardlink("bin/b", "bin/a")]]).unwrap();
        assert_eq!(kept.summary.hard_links, 1);
        assert!(matches!(
            kept.get("bin/b"),
            Some(TreeNode::File { hard_link_to: Some(target), .. }) if target.as_str() == "bin/a"
        ));
        // Implied parents are recorded as directories.
        assert!(matches!(
            kept.get("bin"),
            Some(TreeNode::Directory { implied: true, .. })
        ));
    }

    #[test]
    fn a_whiteout_of_nothing_is_a_no_op() {
        let tree = tree_of(&[vec![file("a", b"1")], vec![file(".wh.ghost", b"")]]).unwrap();
        assert_eq!(names(&tree), ["a"]);
    }

    #[test]
    fn the_tree_index_round_trips_and_tampering_is_refused() {
        let tree = tree_of(&[
            vec![
                dir("app"),
                file("app/x", b"1"),
                symlink("app/y", "x"),
                hardlink("app/z", "app/x"),
            ],
            vec![file("app/w", b"2")],
        ])
        .unwrap();
        let limits = ImportLimits::default();
        let body = tree.body_bytes().unwrap();
        assert_eq!(TreeIndex::from_body(&body, 2, &limits).unwrap(), tree);
        assert!(matches!(
            TreeIndex::from_body(&body, 1, &limits),
            Err(TreeRefusal::LayerOutOfRange { layer: 1, .. })
        ));
        let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        value["entries"].as_array_mut().unwrap().swap(1, 2);
        assert!(matches!(
            TreeIndex::from_body(&serde_json::to_vec(&value).unwrap(), 2, &limits),
            Err(TreeRefusal::Unsorted { .. })
        ));
        let mut orphan: serde_json::Value = serde_json::from_slice(&body).unwrap();
        orphan["entries"].as_array_mut().unwrap().remove(0);
        assert!(matches!(
            TreeIndex::from_body(&serde_json::to_vec(&orphan).unwrap(), 2, &limits),
            Err(TreeRefusal::MissingParent { .. })
        ));
        let mut broken: serde_json::Value = serde_json::from_slice(&body).unwrap();
        broken["entries"][4]["node"]["hard_link_to"] = serde_json::json!("app/w");
        assert!(matches!(
            TreeIndex::from_body(&serde_json::to_vec(&broken).unwrap(), 2, &limits),
            Err(TreeRefusal::BrokenHardLink { .. })
        ));
        let mut escape: serde_json::Value = serde_json::from_slice(&body).unwrap();
        escape["entries"][3]["node"]["target"] = serde_json::json!("../../etc/passwd");
        assert!(matches!(
            TreeIndex::from_body(&serde_json::to_vec(&escape).unwrap(), 2, &limits),
            Err(TreeRefusal::Archive { .. })
        ));
        let mut unknown: serde_json::Value = serde_json::from_slice(&body).unwrap();
        unknown["entries"][0]["node"]["setuid"] = serde_json::json!(true);
        assert!(matches!(
            TreeIndex::from_body(&serde_json::to_vec(&unknown).unwrap(), 2, &limits),
            Err(TreeRefusal::Malformed { .. })
        ));
    }
}

mod import {
    use super::*;
    use crate::foundation::catalog::{
        GrantRequest, ImportRefusal, ReadRefusal, TrustPolicy, TrustRefusal,
    };
    use crate::foundation::ids::SandboxBootGeneration;
    use std::time::Duration;

    #[test]
    fn an_image_imports_through_an_index_into_read_only_objects() {
        let mut h = Harness::new();
        let mut fx =
            two_layer_image().indexed(serde_json::json!({"os": "linux", "architecture": "amd64"}));
        let image = h.import(&mut fx, Scope::Host).unwrap();
        assert_eq!(image.manifest, fx.manifest.digest);
        assert_eq!(image.layers.len(), 2);
        assert!(image.layers.iter().all(|layer| !layer.cache_hit));
        assert_eq!(image.layers[0].reference, fx.layers[0]);
        assert_eq!(image.tree.summary.files, 2);
        let objects = h.catalog.objects(&Scope::Host);
        assert_eq!(objects.len(), 3);
        for object in objects {
            assert_eq!(
                h.catalog.status(&Scope::Host, object),
                ObjectStatus::Published
            );
        }
        // The tree is published as an envelope; its body names app/main and app/new only.
        let reader = execution("sandbox-1");
        let lease = h
            .catalog
            .acquire_lease(
                &Scope::Host,
                &reader,
                image.tree.object,
                Duration::from_secs(60),
            )
            .unwrap();
        let bytes = h
            .catalog
            .open_read(&Scope::Host, &reader, lease)
            .unwrap()
            .read_all()
            .unwrap();
        assert_eq!(&bytes[..8], &TREE_MAGIC);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("app/main") && text.contains("app/new") && !text.contains("app/old"));
        // The catalog's own re-verification runs the stateless verifier again.
        for layer in &image.layers {
            h.catalog.verify_object(&Scope::Host, layer.object).unwrap();
        }
        h.catalog
            .verify_object(&Scope::Host, image.tree.object)
            .unwrap();
        h.reopen();
        assert_eq!(h.catalog.objects(&Scope::Host).len(), 3);
        h.catalog
            .verify_object(&Scope::Host, image.tree.object)
            .unwrap();
    }

    #[test]
    fn hooks_and_entrypoints_are_recorded_as_data_and_never_run() {
        let marker_dir = tempfile::tempdir().unwrap();
        let marker = marker_dir.path().join("pwned");
        let command = format!("touch {}", marker.display());
        let mut h = Harness::new();
        let mut fx = image_with(
            &[(tar_of(&[file("app", b"x")]), LayerCodec::Gzip)],
            |config| {
                config["config"] = serde_json::json!({
                    "Entrypoint": ["/bin/sh", "-c", command],
                    "Cmd": [command],
                    "Healthcheck": {"Test": ["CMD-SHELL", command]},
                    "OnBuild": [format!("RUN {command}")],
                    "Shell": ["/bin/sh", "-c"]
                });
                config["history"] = serde_json::json!([{"created_by": command}]);
            },
            |_| {},
        );
        let image = h.import(&mut fx, Scope::Host).unwrap();
        assert_eq!(image.config.process.entrypoint[2], command);
        assert_eq!(image.config.hooks.on_build, [format!("RUN {command}")]);
        assert_eq!(
            image.config.hooks.healthcheck.as_ref().unwrap().test[1],
            command
        );
        assert_eq!(
            image.config.history[0].created_by.as_deref(),
            Some(command.as_str())
        );
        assert!(!marker.exists(), "an image command ran on the host");
    }

    #[test]
    fn the_module_has_no_process_api() {
        let sources = [
            include_str!("mod.rs"),
            include_str!("config.rs"),
            include_str!("digest.rs"),
            include_str!("document.rs"),
            include_str!("envelope.rs"),
            include_str!("import.rs"),
            include_str!("layer.rs"),
            include_str!("limits.rs"),
            include_str!("overlay.rs"),
            include_str!("tar.rs"),
            include_str!("tree.rs"),
            include_str!("verifier.rs"),
        ];
        let needles = [
            ["std", "::", "process"].concat(),
            ["Command", "::", "new"].concat(),
            ["libc", "::"].concat(),
            [".spa", "wn("].concat(),
            ["std", "::", "net"].concat(),
        ];
        for source in sources {
            for needle in &needles {
                assert!(!source.contains(needle.as_str()), "found {needle}");
            }
        }
    }

    #[test]
    fn a_digest_is_not_trust_and_forged_provenance_is_refused() {
        let mut h = Harness::new();
        let mut fx = two_layer_image();
        let base = h.request(&fx, Scope::Host);
        let forged = |trust: OciTrust| OciImportRequest {
            trust,
            ..base.clone()
        };
        let cases = [
            (
                OciTrust::ChecksumOnly,
                ProvenanceRefusal::ChecksumIsNotTrust,
            ),
            (
                OciTrust::Publisher {
                    publisher: publisher_of(ROGUE_KEY),
                    signature: sign(ROGUE_KEY, &fx.manifest.digest),
                },
                ProvenanceRefusal::PublisherNotTrusted {
                    publisher: publisher_of(ROGUE_KEY),
                },
            ),
            (
                OciTrust::Publisher {
                    publisher: h.publisher,
                    signature: sign(ROGUE_KEY, &fx.manifest.digest),
                },
                ProvenanceRefusal::SignatureRejected {
                    refusal: SignatureRefusal::BadSignature,
                },
            ),
            (
                OciTrust::Publisher {
                    publisher: h.publisher,
                    signature: sign(TRUSTED_KEY, &OciDigest::of(b"a different manifest")),
                },
                ProvenanceRefusal::SignatureRejected {
                    refusal: SignatureRefusal::BadSignature,
                },
            ),
        ];
        for (trust, refusal) in cases {
            assert_eq!(
                h.import_request(&mut fx, &forged(trust)),
                Err(OciImportError::Provenance { refusal })
            );
        }
        // A publisher the policy trusts but whose key nobody knows.
        let unknown = publisher_of(b"unknown key");
        h.catalog.set_trust_policy(
            ArtifactClass::OciLayer,
            TrustPolicy::new()
                .trust_publisher(h.publisher)
                .trust_publisher(unknown),
        );
        assert_eq!(
            h.import_request(
                &mut fx,
                &forged(OciTrust::Publisher {
                    publisher: unknown,
                    signature: vec![0; 32]
                })
            ),
            Err(OciImportError::Provenance {
                refusal: ProvenanceRefusal::SignatureRejected {
                    refusal: SignatureRefusal::UnknownPublisher
                }
            })
        );
        assert!(h.catalog.objects(&Scope::Host).is_empty());
    }

    /// Imports image A, then offers the catalog A's valid attestation for content that is
    /// not A's: the verifier refuses it at the catalog itself, not only in the importer.
    #[test]
    fn the_catalog_verifier_refuses_attestations_bound_to_other_content() {
        use crate::foundation::catalog::{
            ImportRequest, ImportStart, ImportStatus, ObjectMetadata, ObjectRole, SourceIdentity,
            TrustClaim, Uninterrupted,
        };
        use crate::sandbox_contract::oci::envelope::layer_envelope;

        struct Bytes(Vec<u8>);
        impl crate::foundation::catalog::ImportSource for Bytes {
            fn identity(&self) -> SourceIdentity {
                SourceIdentity::describe("test", "forged")
            }
            fn length_bytes(&mut self) -> Result<u64, crate::foundation::catalog::SourceError> {
                Ok(self.0.len() as u64)
            }
            fn read_at(
                &mut self,
                offset_bytes: u64,
                buffer: &mut [u8],
            ) -> Result<usize, crate::foundation::catalog::SourceError> {
                let rest = &self.0[offset_bytes as usize..];
                let count = rest.len().min(buffer.len());
                buffer[..count].copy_from_slice(&rest[..count]);
                Ok(count)
            }
        }

        let mut h = Harness::new();
        let publisher = h.publisher;
        let fx = two_layer_image();
        let other_tar = tar_of(&[file("malware", b"evil")]);
        let (other_blob, other_diff) = layer(&other_tar, LayerCodec::Gzip);
        let other = layer_envelope(&other_blob, other_diff).unwrap();
        let real_blob = verified(fx.layer_bytes[0].clone(), fx.layers[0].media_type);
        let real_diff = OciDigest::of(&tar_of(&[
            dir("app"),
            file("app/main", b"#!/bin/sh\necho hi\n"),
            file("app/old", b"old"),
        ]));
        let real = layer_envelope(&real_blob, real_diff).unwrap();
        let signature = sign(TRUSTED_KEY, &fx.manifest.digest);
        let attest =
            |prefix: &[u8], manifest: &crate::foundation::catalog::ImportManifest| OciAttestation {
                manifest: fx.manifest_bytes.clone(),
                config: fx.config_bytes.clone(),
                signature: signature.clone(),
                prefix: prefix.to_vec(),
                import_manifest: manifest.clone(),
            };
        let request = |manifest: crate::foundation::catalog::ImportManifest, trust: TrustClaim| {
            ImportRequest {
                operation: crate::foundation::ids::OperationId::new("op-forge").unwrap(),
                execution: execution("forger"),
                scope: Scope::Host,
                class: ArtifactClass::OciLayer,
                role: ObjectRole::Original,
                manifest,
                trust,
                depends_on: Default::default(),
                metadata: ObjectMetadata::new(),
            }
        };
        let refused = |h: &mut Harness, manifest, trust| match h.catalog.begin_import(
            request(manifest, trust),
            SourceIdentity::describe("test", "forged"),
        ) {
            Err(ImportRefusal::Trust { refusal }) => refusal,
            other => panic!("expected a trust refusal, got {other:?}"),
        };
        let other_manifest = other.import_manifest(4096);
        let real_manifest = real.import_manifest(4096);

        // A's attestation (prefix and extent table of A's layer) on B's content.
        let refusal = refused(
            &mut h,
            other_manifest.clone(),
            TrustClaim::Publisher {
                publisher,
                attestation: attest(real.prefix(), &real_manifest).encode(),
            },
        );
        assert!(matches!(
            refusal,
            TrustRefusal::AttestationRejected {
                rejection: crate::foundation::catalog::VerifierRejection::AttestationInvalid,
                ..
            }
        ));
        // B's own prefix and table, signed over A's manifest, which does not list B.
        let refusal = refused(
            &mut h,
            other_manifest.clone(),
            TrustClaim::Publisher {
                publisher,
                attestation: attest(other.prefix(), &other_manifest).encode(),
            },
        );
        assert!(matches!(refusal, TrustRefusal::AttestationRejected { .. }));
        // A valid attestation claimed for a trusted publisher who did not sign it.
        let rogue_trusted = publisher_of(ROGUE_KEY);
        h.catalog.set_trust_policy(
            ArtifactClass::OciLayer,
            TrustPolicy::new()
                .trust_publisher(publisher)
                .trust_publisher(rogue_trusted),
        );
        let refusal = refused(
            &mut h,
            real_manifest.clone(),
            TrustClaim::Publisher {
                publisher: rogue_trusted,
                attestation: attest(real.prefix(), &real_manifest).encode(),
            },
        );
        assert!(matches!(refusal, TrustRefusal::AttestationRejected { .. }));
        // A checksum alone, and a publisher the policy does not back.
        assert_eq!(
            refused(&mut h, real_manifest.clone(), TrustClaim::ChecksumOnly),
            TrustRefusal::ChecksumIsNotTrust {
                class: ArtifactClass::OciLayer
            }
        );
        assert!(matches!(
            refused(
                &mut h,
                real_manifest.clone(),
                TrustClaim::Publisher {
                    publisher: publisher_of(b"nobody"),
                    attestation: attest(real.prefix(), &real_manifest).encode(),
                }
            ),
            TrustRefusal::PublisherNotTrusted { .. }
        ));
        assert!(h.catalog.objects(&Scope::Host).is_empty());

        // A's true prefix in front of a body that is not A's blob: the claim authenticates,
        // and the verifier's read-back of the committed bytes refuses it.
        let mut swapped = real.bytes[..real.prefix_bytes].to_vec();
        let mut body = fx.layer_bytes[0].clone();
        body[20] ^= 0xff;
        swapped.extend_from_slice(&body);
        let swapped_envelope = super::super::envelope::Envelope {
            prefix_bytes: real.prefix_bytes,
            bytes: swapped.clone(),
        };
        let swapped_manifest = swapped_envelope.import_manifest(4096);
        let start = h
            .catalog
            .begin_import(
                request(
                    swapped_manifest.clone(),
                    TrustClaim::Publisher {
                        publisher,
                        attestation: attest(real.prefix(), &swapped_manifest).encode(),
                    },
                ),
                SourceIdentity::describe("test", "forged"),
            )
            .unwrap();
        let ImportStart::Started(ticket) = start else {
            panic!("{start:?}")
        };
        let status = h
            .catalog
            .drive_import(&ticket, &mut Bytes(swapped), &mut Uninterrupted)
            .unwrap();
        assert!(matches!(status, ImportStatus::Failed { .. }), "{status:?}");
        assert!(h.catalog.objects(&Scope::Host).is_empty());

        // Once A is published, a cache hit is still authenticated: the valid claim gets the
        // published object, the forged one is refused although the bytes are there.
        let image = h.import(&mut two_layer_image(), Scope::Host).unwrap();
        match h.catalog.begin_import(
            request(
                real_manifest.clone(),
                TrustClaim::Publisher {
                    publisher,
                    attestation: attest(real.prefix(), &real_manifest).encode(),
                },
            ),
            SourceIdentity::describe("test", "forged"),
        ) {
            Ok(ImportStart::AlreadyPublished(object)) => assert_eq!(object, image.layers[0].object),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            refused(
                &mut h,
                real_manifest.clone(),
                TrustClaim::Publisher {
                    publisher: rogue_trusted,
                    attestation: attest(real.prefix(), &real_manifest).encode(),
                }
            ),
            TrustRefusal::AttestationRejected { .. }
        ));
    }

    #[test]
    fn a_short_quota_publishes_nothing() {
        let mut probe = Harness::new();
        probe.import(&mut two_layer_image(), tenant("a")).unwrap();
        let needed = probe.catalog.quota_usage(&tenant("a")).published_bytes;
        for (quota, accepted) in [(needed - 1, false), (needed, true)] {
            let h = Harness::new();
            let dir = tempfile::tempdir().unwrap();
            let config = h.catalog.config().clone().with_quota(tenant("d"), quota);
            let mut registry = crate::foundation::catalog::VerifierRegistry::new();
            registry.register(Box::new(h.importer.verifier())).unwrap();
            let (mut catalog, _) = crate::foundation::catalog::Catalog::open(
                dir.path(),
                config,
                registry,
                h.clock.clone(),
            )
            .unwrap();
            let mut fx = two_layer_image();
            let request = h.request(&fx, tenant("d"));
            let result = h.importer.import(&mut catalog, &mut fx.blobs, &request);
            if accepted {
                assert!(result.is_ok());
                assert_eq!(catalog.quota_usage(&tenant("d")).published_bytes, needed);
            } else {
                assert_eq!(
                    result,
                    Err(OciImportError::QuotaShort {
                        needed_bytes: needed,
                        available_bytes: needed - 1
                    })
                );
                assert!(catalog.objects(&tenant("d")).is_empty());
            }
        }
    }

    #[test]
    fn corrupt_or_substituted_blobs_are_refused_before_parsing() {
        let mut h = Harness::new();
        let mut fx = two_layer_image();
        let digest = fx.layers[1].digest;
        let mut corrupt = fx.layer_bytes[1].clone();
        corrupt[10] ^= 0x01;
        fx.blobs.insert_as(digest, corrupt.clone());
        assert_eq!(
            h.import(&mut fx, Scope::Host),
            Err(OciImportError::Blob {
                at: BlobAt::Layer { index: 1 },
                refusal: BlobRefusal::DigestMismatch {
                    declared: digest,
                    found: OciDigest::of(&corrupt)
                }
            })
        );
        fx.blobs.insert_as(digest, fx.layer_bytes[1][..20].to_vec());
        assert!(matches!(
            h.import(&mut fx, Scope::Host),
            Err(OciImportError::Blob {
                at: BlobAt::Layer { index: 1 },
                refusal: BlobRefusal::SizeMismatch { .. }
            })
        ));
        let mut missing = two_layer_image();
        missing.blobs = MemoryBlobs::new();
        assert!(matches!(
            h.import(&mut missing, Scope::Host),
            Err(OciImportError::Source {
                at: BlobAt::Root,
                ..
            })
        ));
        assert!(h.catalog.objects(&Scope::Host).is_empty());
    }

    #[test]
    fn one_bad_layer_publishes_nothing() {
        let mut h = Harness::new();
        let mut fx = image(&[
            (tar_of(&[file("good", b"ok")]), LayerCodec::Gzip),
            (raw_tar(&[raw_file("../escape", b"x")]), LayerCodec::Zstd),
        ]);
        assert_eq!(
            h.import(&mut fx, Scope::Host),
            Err(OciImportError::Layer {
                index: 1,
                refusal: unsafe_name(0, NameRefusal::Traversal { index: 0 })
            })
        );
        assert!(h.catalog.objects(&Scope::Host).is_empty());
        let limits = ImportLimits {
            max_layer_expanded_bytes: 1 << 20,
            max_ratio: 1_000_000,
            ..ImportLimits::default()
        };
        let mut h = Harness::with_limits(limits);
        let mut bomb = image(&[(
            tar_of(&[file("zeros", &vec![0u8; 4 << 20])]),
            LayerCodec::Gzip,
        )]);
        assert!(matches!(
            h.import(&mut bomb, Scope::Host),
            Err(OciImportError::Layer {
                index: 0,
                refusal: LayerRefusal::Stream {
                    refusal: StreamRefusal::ExpandedTooLarge { .. }
                }
            })
        ));
        assert!(h.catalog.objects(&Scope::Host).is_empty());
    }

    #[test]
    fn declared_sizes_are_bounded_before_fetching() {
        let limits = ImportLimits {
            max_layer_compressed_bytes: 64,
            max_image_compressed_bytes: 64,
            ..ImportLimits::default()
        };
        let mut h = Harness::with_limits(limits);
        let mut fx = two_layer_image();
        assert!(matches!(
            h.import(&mut fx, Scope::Host),
            Err(OciImportError::Blob {
                at: BlobAt::Layer { index: 0 },
                refusal: BlobRefusal::DeclaredTooLarge {
                    limit_bytes: 64,
                    ..
                }
            })
        ));
        let small_documents = ImportLimits {
            max_document_bytes: 16,
            ..ImportLimits::default()
        };
        let mut h = Harness::with_limits(small_documents);
        assert!(matches!(
            h.import(&mut two_layer_image(), Scope::Host),
            Err(OciImportError::Blob {
                at: BlobAt::Root,
                refusal: BlobRefusal::DeclaredTooLarge {
                    limit_bytes: 16,
                    ..
                }
            })
        ));
    }

    #[test]
    fn platform_media_type_and_backing_files_are_checked_end_to_end() {
        let mut h = Harness::new();
        let mut arm =
            two_layer_image().indexed(serde_json::json!({"os": "linux", "architecture": "arm64"}));
        assert!(matches!(
            h.import(&mut arm, Scope::Host),
            Err(OciImportError::Document {
                refusal: DocumentRefusal::NoMatchingPlatform { .. }
            })
        ));
        let mut wrong_config = image_with(
            &[(tar_of(&[file("f", b"x")]), LayerCodec::Gzip)],
            |config| config["architecture"] = serde_json::json!("riscv64"),
            |_| {},
        );
        assert!(matches!(
            h.import(&mut wrong_config, Scope::Host),
            Err(OciImportError::Config {
                refusal: ConfigRefusal::PlatformMismatch { .. }
            })
        ));
        let mut foreign = image_with(
            &[(tar_of(&[file("f", b"x")]), LayerCodec::Gzip)],
            |_| {},
            |manifest| manifest["layers"][0]["urls"] = serde_json::json!(["https://cdn.example/l"]),
        );
        assert_eq!(
            h.import(&mut foreign, Scope::Host),
            Err(OciImportError::Document {
                refusal: DocumentRefusal::ForeignUrls {
                    at: DescriptorAt::Layer { index: 0 }
                }
            })
        );
        let mut as_config = two_layer_image();
        as_config.root.media_type = MediaType::ImageConfig;
        assert_eq!(
            h.import(&mut as_config, Scope::Host),
            Err(OciImportError::RootMediaType {
                media_type: MediaType::ImageConfig
            })
        );
        let mut diff_mismatch = image_with(
            &[(tar_of(&[file("f", b"x")]), LayerCodec::Gzip)],
            |config| {
                config["rootfs"]["diff_ids"] =
                    serde_json::json!([OciDigest::of(b"other").to_string()])
            },
            |_| {},
        );
        assert!(matches!(
            h.import(&mut diff_mismatch, Scope::Host),
            Err(OciImportError::Layer {
                index: 0,
                refusal: LayerRefusal::Stream {
                    refusal: StreamRefusal::DiffIdMismatch { .. }
                }
            })
        ));
    }

    #[test]
    fn the_parser_never_runs_in_a_host_process_or_host_mount() {
        let mut h = Harness::new();
        let mut fx = two_layer_image();
        for method in [
            InspectionMethod::HostProcessParser,
            InspectionMethod::HostMount,
        ] {
            let request = OciImportRequest {
                inspection: method,
                ..h.request(&fx, Scope::Host)
            };
            assert!(matches!(
                h.import_request(&mut fx, &request),
                Err(OciImportError::Inspection { .. })
            ));
        }
        let helper = OciImportRequest {
            inspection: InspectionMethod::ConstrainedHelper,
            ..h.request(&fx, Scope::Host)
        };
        assert!(h.import_request(&mut fx, &helper).is_ok());
    }

    #[test]
    fn user_selected_images_stay_in_the_tenants_own_scope() {
        let mut h = Harness::new();
        let mut fx = two_layer_image();
        let request = |scope: Scope| OciImportRequest {
            trust: OciTrust::UserSelected,
            ..h.request(&fx, scope)
        };
        let tenant_request = request(tenant("a"));
        let host_request = request(Scope::Host);
        assert!(h.import_request(&mut fx, &tenant_request).is_ok());
        assert!(matches!(
            h.import_request(&mut fx, &host_request),
            Err(OciImportError::Catalog {
                step: CatalogStep::Layer { index: 0 },
                refusal: ImportRefusal::Trust {
                    refusal: TrustRefusal::UserSelectionOutsideTenantScope { .. }
                }
            })
        ));
    }

    #[test]
    fn cache_hits_enforce_the_original_access_policy() {
        let mut h = Harness::new();
        let mut fx = two_layer_image();
        let a = h.import(&mut fx, tenant("a")).unwrap();
        // Again in the same scope: every object is a cache hit, re-checked by the catalog.
        let again = h.import(&mut fx, tenant("a")).unwrap();
        assert!(again.layers.iter().all(|layer| layer.cache_hit) && again.tree.cache_hit);
        assert_eq!(again.objects(), a.objects());
        // Another scope never receives a's objects: it gets its own under its own quota.
        let b = h.import(&mut fx, tenant("b")).unwrap();
        assert!(b.layers.iter().all(|layer| !layer.cache_hit) && !b.tree.cache_hit);
        for (ours, theirs) in b.layers.iter().zip(&a.layers) {
            assert_ne!(ours.object, theirs.object);
        }
        assert_eq!(
            h.catalog.status(&tenant("b"), a.tree.object),
            ObjectStatus::Absent
        );
        // A scope without quota is refused instead of being handed another scope's copy.
        assert!(matches!(
            h.import(&mut fx, tenant("c")),
            Err(OciImportError::QuotaShort {
                available_bytes: 0,
                ..
            })
        ));
        assert!(h.catalog.objects(&tenant("c")).is_empty());
        // Withdrawing the publisher: the cached objects are quarantined, and a cache hit
        // is refused by the catalog's own re-check, not served.
        h.catalog
            .set_trust_policy(ArtifactClass::OciLayer, TrustPolicy::new());
        assert!(matches!(
            h.catalog.status(&tenant("a"), a.tree.object),
            ObjectStatus::Quarantined { .. }
        ));
        assert!(matches!(
            h.import(&mut fx, tenant("a")),
            Err(OciImportError::Provenance {
                refusal: ProvenanceRefusal::PublisherNotTrusted { .. }
            })
        ));
        let user = OciImportRequest {
            trust: OciTrust::UserSelected,
            ..h.request(&fx, tenant("a"))
        };
        assert!(matches!(
            h.import_request(&mut fx, &user),
            Err(OciImportError::Catalog {
                refusal: ImportRefusal::Trust {
                    refusal: TrustRefusal::UserSelectionNotAccepted { .. }
                },
                ..
            })
        ));
    }

    fn overlay_request(
        image: &ImportedImage,
        reader: Scope,
        sandbox: &str,
        generation: u64,
    ) -> OverlayRequest {
        OverlayRequest {
            reader,
            sandbox: execution(sandbox),
            generation: SandboxBootGeneration::new(generation),
            image: image.objects(),
            writable: WritableCache::PrivateToSandbox,
            lease_duration: Duration::from_secs(600),
        }
    }

    #[test]
    fn each_sandbox_gets_its_own_overlay_over_read_only_bases() {
        let mut h = Harness::new();
        let image = h.import(&mut two_layer_image(), Scope::Host).unwrap();
        let mut overlays = OverlayRegistry::new(h.clock.clone(), 8);
        let one = overlays
            .bind(
                &mut h.catalog,
                overlay_request(&image, Scope::Host, "sandbox-1", 1),
            )
            .unwrap();
        let two = overlays
            .bind(
                &mut h.catalog,
                overlay_request(&image, Scope::Host, "sandbox-2", 1),
            )
            .unwrap();
        assert_ne!(one.overlay, two.overlay);
        assert_eq!(one.tree, two.tree);
        assert_eq!(one.upper.owner, execution("sandbox-1"));
        assert!(!one.upper.shared && !two.upper.shared);
        assert_eq!(one.materialization, Materialization::InsideGuestOnly);
        assert_eq!(one.leases.len(), 3);
        // Never shared: another sandbox, or this one after a reboot, cannot use it.
        assert_eq!(
            overlays.attach(
                one.overlay,
                &execution("sandbox-2"),
                SandboxBootGeneration::new(1)
            ),
            Err(OverlayRefusal::OtherSandbox)
        );
        assert_eq!(
            overlays.attach(
                one.overlay,
                &execution("sandbox-1"),
                SandboxBootGeneration::new(2)
            ),
            Err(OverlayRefusal::StaleGeneration {
                bound: SandboxBootGeneration::new(1),
                presented: SandboxBootGeneration::new(2)
            })
        );
        assert!(overlays
            .attach(
                one.overlay,
                &execution("sandbox-1"),
                SandboxBootGeneration::new(1)
            )
            .is_ok());
        assert_eq!(
            overlays.bind(
                &mut h.catalog,
                overlay_request(&image, Scope::Host, "sandbox-1", 1)
            ),
            Err(OverlayRefusal::AlreadyBound {
                overlay: one.overlay
            })
        );
        let rebooted = overlays
            .bind(
                &mut h.catalog,
                overlay_request(&image, Scope::Host, "sandbox-1", 2),
            )
            .unwrap();
        assert_ne!(rebooted.overlay, one.overlay);
        assert_eq!(
            overlays.release(&mut h.catalog, one.overlay, &execution("sandbox-2")),
            Err(OverlayRefusal::OtherSandbox)
        );
        overlays
            .release(&mut h.catalog, one.overlay, &execution("sandbox-1"))
            .unwrap();
        assert_eq!(overlays.len(), 2);
    }

    #[test]
    fn shared_mutable_caches_and_the_importer_as_consumer_are_refused() {
        let mut h = Harness::new();
        let image = h.import(&mut two_layer_image(), Scope::Host).unwrap();
        let mut overlays = OverlayRegistry::new(h.clock.clone(), 8);
        let shared = OverlayRequest {
            writable: WritableCache::Shared {
                name: "pip-cache".into(),
            },
            ..overlay_request(&image, Scope::Host, "sandbox-1", 1)
        };
        assert_eq!(
            overlays.bind(&mut h.catalog, shared),
            Err(OverlayRefusal::SharedMutableCache)
        );
        assert_eq!(
            overlays.bind(
                &mut h.catalog,
                overlay_request(&image, Scope::Host, "importer-1", 1)
            ),
            Err(OverlayRefusal::ImporterIsConsumer)
        );
        let mut tight = OverlayRegistry::new(h.clock.clone(), 1);
        tight
            .bind(
                &mut h.catalog,
                overlay_request(&image, Scope::Host, "sandbox-1", 1),
            )
            .unwrap();
        assert_eq!(
            tight.bind(
                &mut h.catalog,
                overlay_request(&image, Scope::Host, "sandbox-2", 1)
            ),
            Err(OverlayRefusal::TooManyOverlays { limit: 1 })
        );
    }

    #[test]
    fn another_scope_reads_the_bases_only_under_the_owners_grant() {
        let mut h = Harness::new();
        let image = h.import(&mut two_layer_image(), tenant("a")).unwrap();
        let mut overlays = OverlayRegistry::new(h.clock.clone(), 8);
        assert!(matches!(
            overlays.bind(
                &mut h.catalog,
                overlay_request(&image, tenant("b"), "b-sandbox", 1)
            ),
            Err(OverlayRefusal::NotReadable {
                refusal: ReadRefusal::NotGranted { .. },
                ..
            })
        ));
        let expires_at = h.clock.now().saturating_add(Duration::from_secs(3600));
        let mut grants = Vec::new();
        for object in
            std::iter::once(image.tree.object).chain(image.layers.iter().map(|layer| layer.object))
        {
            grants.push(
                h.catalog
                    .grant(
                        &tenant("a"),
                        GrantRequest {
                            object,
                            grantee: tenant("b"),
                            execution: Some(execution("b-sandbox")),
                            expires_at,
                        },
                    )
                    .unwrap(),
            );
        }
        let granted = overlays
            .bind(
                &mut h.catalog,
                overlay_request(&image, tenant("b"), "b-sandbox", 1),
            )
            .unwrap();
        assert_eq!(granted.base_owner, tenant("a"));
        // The grant names one execution; another sandbox of b gets nothing.
        assert!(matches!(
            overlays.bind(
                &mut h.catalog,
                overlay_request(&image, tenant("b"), "b-other", 1)
            ),
            Err(OverlayRefusal::NotReadable { .. })
        ));
        for grant in grants {
            h.catalog.revoke_grant(&tenant("a"), grant).unwrap();
        }
        assert!(matches!(
            overlays.bind(
                &mut h.catalog,
                overlay_request(&image, tenant("b"), "b-sandbox", 2)
            ),
            Err(OverlayRefusal::NotReadable { .. })
        ));
        // Withdrawn trust quarantines the bases, and no overlay is bound over them.
        h.catalog
            .set_trust_policy(ArtifactClass::OciLayer, TrustPolicy::new());
        assert!(matches!(
            overlays.bind(
                &mut h.catalog,
                overlay_request(&image, tenant("a"), "a-sandbox", 1)
            ),
            Err(OverlayRefusal::NotReadable {
                refusal: ReadRefusal::Quarantined { .. },
                ..
            })
        ));
    }

    #[test]
    fn importer_limits_must_be_enforceable() {
        let signatures = std::sync::Arc::new(FakeSignatures::with_keys(&[TRUSTED_KEY]));
        assert_eq!(
            OciImporter::new(
                ImportLimits {
                    max_ratio: 0,
                    ..ImportLimits::default()
                },
                signatures.clone()
            )
            .err(),
            Some(LimitsProblem::RatioBelowOne)
        );
        assert!(OciVerifier::new(signatures, ImportLimits::default()).is_ok());
    }
}
