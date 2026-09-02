use crate::sources::{Source, SourceConfig};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;

/// Whether anything in this chain, or in any chain nested below it, emits PARTIAL response
/// trains — a response delivered as several messages, only the last of which carries the
/// request id.
fn chain_emits_partial_responses(chain: &crate::config::chain::TransformChainConfig) -> bool {
    chain.0.iter().any(|config| {
        config.emits_partial_responses()
            || config
                .get_sub_chain_configs()
                .iter()
                .any(|(sub_chain, _)| chain_emits_partial_responses(sub_chain))
    })
}

/// Collects every transform that would be handed partial response trains it has not
/// declared it can handle.
///
/// A chain is judged as a whole rather than per position: partials travel UP it from
/// whichever transform emits them, so every transform above the emitter sees them, and a
/// sub-chain that emits hands them to the transform that owns it — which makes the
/// enclosing chain a streaming one too. That is deliberately conservative; refusing to
/// start is always recoverable, silently feeding a transform a shape it cannot read is not.
///
/// Mirrors `collect_chain_names` in `run_chains`, including its behaviour of visiting a sub-chain
/// once per worker for transforms like ParallelMap that report the same chain repeatedly.
fn collect_partial_response_errors(
    chain: &crate::config::chain::TransformChainConfig,
    chain_path: &str,
    errors: &mut Vec<String>,
) {
    if chain_emits_partial_responses(chain) {
        for config in chain.0.iter() {
            if !config.accepts_partial_responses() {
                errors.push(format!(
                    "Transform {} named {:?} in {chain_path} requires whole response trains, but this chain streams partial ones. Set stream_threshold_bytes: 0 on the sink, or remove the transform.",
                    config.typetag_name(),
                    config.get_name(),
                ));
            }
        }
    }

    for config in chain.0.iter() {
        for (sub_chain, sub_chain_name) in config.get_sub_chain_configs() {
            let sub_chain_path = format!("{chain_path} -> subchain {sub_chain_name:?}");
            collect_partial_response_errors(sub_chain, &sub_chain_path, errors);
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    pub sources: Vec<SourceConfig>,
}

impl Topology {
    /// Load the topology.yaml from the provided path into a Topology instance
    pub fn from_file(filepath: &str) -> Result<Topology> {
        let file = std::fs::File::open(filepath)
            .with_context(|| format!("Couldn't open the topology file {}", filepath))?;

        let deserializer = serde_yaml::Deserializer::from_reader(file);
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer)
            .with_context(|| format!("Failed to parse topology file {}", filepath))
    }

    /// Generate the yaml representation of this instance
    pub fn serialize(&self) -> Result<String> {
        let mut output = vec![];
        let mut serializer = serde_yaml::Serializer::new(&mut output);
        serde_yaml::with::singleton_map_recursive::serialize(self, &mut serializer)?;
        Ok(String::from_utf8(output).unwrap())
    }

    pub async fn run_chains(
        &self,
        trigger_shutdown_rx: watch::Receiver<bool>,
        mut hot_reload_listeners: HashMap<u16, TcpListener>,
    ) -> Result<Vec<Source>> {
        let mut sources: Vec<Source> = Vec::new();

        let mut topology_errors = String::new();

        #[derive(Default)]
        struct NameValidationState {
            source_uses: BTreeMap<String, Vec<String>>,
            transform_uses: BTreeMap<String, Vec<String>>,
            chain_uses: BTreeMap<String, Vec<String>>,
        }

        impl NameValidationState {
            fn register_source(&mut self, name: &str, usage: String) {
                self.source_uses
                    .entry(name.to_string())
                    .or_default()
                    .push(usage);
            }

            fn register_transform(&mut self, name: &str, usage: String) {
                self.transform_uses
                    .entry(name.to_string())
                    .or_default()
                    .push(usage);
            }

            fn register_chain(&mut self, name: &str, usage: String) {
                self.chain_uses
                    .entry(name.to_string())
                    .or_default()
                    .push(usage);
            }

            fn duplicate_names(map: BTreeMap<String, Vec<String>>) -> Vec<(String, Vec<String>)> {
                map.into_iter().filter(|(_, uses)| uses.len() > 1).collect()
            }
        }

        // Validate name uniqueness across sources, transforms, and chains in a single traversal.
        let mut name_state = NameValidationState::default();
        let mut partial_response_errors: Vec<String> = Vec::new();

        fn collect_chain_names(
            state: &mut NameValidationState,
            chain: &crate::config::chain::TransformChainConfig,
            chain_path: &str,
        ) {
            for (transform_index, config) in chain.0.iter().enumerate() {
                let transform_name = config.get_name();
                let transform_type = config.typetag_name();
                state.register_transform(
                    transform_name,
                    format!(
                        "Transform[{transform_index}] {transform_type} named {transform_name:?} in {chain_path}"
                    ),
                );

                for (sub_chain, sub_chain_name) in config.get_sub_chain_configs() {
                    let sub_chain_path = format!(
                        "{chain_path} -> subchain {sub_chain_name:?} (from Transform {transform_type} named {transform_name:?})"
                    );
                    state.register_chain(
                        &sub_chain_name,
                        format!("chain {sub_chain_name:?} at {sub_chain_path}"),
                    );
                    collect_chain_names(state, sub_chain, &sub_chain_path);
                }
            }
        }

        for (index, source) in self.sources.iter().enumerate() {
            let source_name = source.get_name();
            name_state.register_source(source_name, format!("source[{index}] {source_name:?}"));
            name_state.register_chain(
                source_name,
                format!("root chain for source[{index}] {source_name:?}"),
            );
            let root_chain_path = format!("source[{index}] {source_name:?} chain {source_name:?}");
            collect_chain_names(&mut name_state, source.get_chain_config(), &root_chain_path);
            collect_partial_response_errors(
                source.get_chain_config(),
                &root_chain_path,
                &mut partial_response_errors,
            );
        }

        let duplicate_sources = NameValidationState::duplicate_names(name_state.source_uses);
        if !duplicate_sources.is_empty() {
            writeln!(topology_errors, "Duplicate source names detected:")?;
            for (name, usages) in duplicate_sources {
                writeln!(topology_errors, "  {name:?} used by:")?;
                for usage in usages {
                    writeln!(topology_errors, "    {usage}")?;
                }
            }
        }

        let duplicate_transforms = NameValidationState::duplicate_names(name_state.transform_uses);
        if !duplicate_transforms.is_empty() {
            writeln!(topology_errors, "Duplicate transform names detected:")?;
            for (name, usages) in duplicate_transforms {
                writeln!(topology_errors, "  {name:?} used by:")?;
                for usage in usages {
                    writeln!(topology_errors, "    {usage}")?;
                }
            }
        }

        let duplicate_chains = NameValidationState::duplicate_names(name_state.chain_uses);
        if !duplicate_chains.is_empty() {
            writeln!(topology_errors, "Duplicate chain names detected:")?;
            for (name, usages) in duplicate_chains {
                writeln!(topology_errors, "  {name:?} used by:")?;
                for usage in usages {
                    writeln!(topology_errors, "    {usage}")?;
                }
            }
        }

        if !partial_response_errors.is_empty() {
            writeln!(
                topology_errors,
                "Transforms that cannot receive the partial response trains their chain streams:"
            )?;
            for error in &partial_response_errors {
                writeln!(topology_errors, "  {error}")?;
            }
        }

        for source in &self.sources {
            match source
                .build(trigger_shutdown_rx.clone(), &mut hot_reload_listeners)
                .await
            {
                Ok(source) => sources.push(source),
                Err(source_errors) => {
                    if !source_errors.is_empty() {
                        topology_errors.push_str(&source_errors.join("\n"));
                        topology_errors.push('\n');
                    }
                }
            };
        }

        if !topology_errors.is_empty() {
            return Err(anyhow!("Topology errors\n{topology_errors}"));
        }

        // This info log is considered part of our external API.
        // Users rely on this to know when shotover is ready in their integration tests.
        // In production they would probably just have some kind of retry mechanism though.
        info!("Shotover is now accepting inbound connections");
        Ok(sources)
    }
}

#[cfg(all(test, feature = "valkey", feature = "cassandra"))]
mod topology_tests {
    use crate::config::chain::TransformChainConfig;
    use crate::config::topology::Topology;
    use crate::sources::cassandra::CassandraSourceConfig;
    use crate::transforms::TransformConfig;
    use crate::transforms::coalesce::CoalesceConfig;
    use crate::transforms::debug::printer::DebugPrinterConfig;
    use crate::transforms::null::NullSinkConfig;
    use crate::{
        sources::{Source, SourceConfig, valkey::ValkeySourceConfig},
        transforms::{
            parallel_map::ParallelMapConfig, tee::ConsistencyBehaviorConfig, tee::TeeConfig,
            valkey::cache::ValkeyConfig as ValkeyCacheConfig,
        },
    };
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use tokio::sync::watch;

    fn create_source_from_chain_valkey(
        transforms: Vec<Box<dyn TransformConfig>>,
    ) -> Vec<SourceConfig> {
        vec![SourceConfig::Valkey(ValkeySourceConfig {
            name: "foo".to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            connection_limit: None,
            hard_connection_limit: None,
            tls: None,
            timeout: None,
            chain: TransformChainConfig(transforms),
        })]
    }

    fn create_source_from_chain_cassandra(
        transforms: Vec<Box<dyn TransformConfig>>,
    ) -> Vec<SourceConfig> {
        vec![SourceConfig::Cassandra(CassandraSourceConfig {
            name: "foo".to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            connection_limit: None,
            hard_connection_limit: None,
            tls: None,
            timeout: None,
            chain: TransformChainConfig(transforms),
            transport: None,
        })]
    }

    async fn run_test_topology_valkey(
        transforms: Vec<Box<dyn TransformConfig>>,
    ) -> anyhow::Result<Vec<Source>> {
        let sources = create_source_from_chain_valkey(transforms);

        let topology = Topology { sources };

        let (_sender, trigger_shutdown_rx) = watch::channel::<bool>(false);

        topology
            .run_chains(trigger_shutdown_rx, HashMap::new())
            .await
    }

    async fn run_test_topology_cassandra(
        transforms: Vec<Box<dyn TransformConfig>>,
    ) -> anyhow::Result<Vec<Source>> {
        let sources = create_source_from_chain_cassandra(transforms);

        let topology = Topology { sources };

        let (_sender, trigger_shutdown_rx) = watch::channel::<bool>(false);

        topology
            .run_chains(trigger_shutdown_rx, HashMap::new())
            .await
    }

    #[tokio::test]
    async fn test_validate_chain_empty_chain() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    Chain cannot be empty
"#;

        let error = run_test_topology_valkey(vec![])
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_chain_valid_chain() {
        run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "debug".to_string(),
            }),
            Box::new(NullSinkConfig {
                name: "sink".to_string(),
            }),
        ])
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_validate_coalesce_neither_flush_field() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    Coalesce:
      Provide at least one of:
      * flush_when_buffered_message_count
      * flush_when_millis_since_last_flush (must be greater than 0)
    
      But none of them were provided.
      Check https://shotover.io/docs/latest/transforms.html#coalesce for more information.
"#;

        let error = run_test_topology_valkey(vec![
            Box::new(CoalesceConfig {
                name: "coalesce".to_string(),
                flush_when_buffered_message_count: None,
                flush_when_millis_since_last_flush: None,
            }),
            Box::new(NullSinkConfig {
                name: "sink".to_string(),
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_coalesce_millis_zero() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    Coalesce:
      flush_when_millis_since_last_flush must be greater than 0 when set.
      Check https://shotover.io/docs/latest/transforms.html#coalesce for more information.
"#;

        let error = run_test_topology_valkey(vec![
            Box::new(CoalesceConfig {
                name: "coalesce".to_string(),
                flush_when_buffered_message_count: Some(100),
                flush_when_millis_since_last_flush: Some(0),
            }),
            Box::new(NullSinkConfig {
                name: "sink".to_string(),
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_chain_terminating_in_middle() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    Terminating Transform NullSink named "sink-1" is not last in chain. Terminating Transform must be last in chain.
"#;

        let error = run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "debug".to_string(),
            }),
            Box::new(NullSinkConfig {
                name: "sink-1".to_string(),
            }),
            Box::new(NullSinkConfig {
                name: "sink-2".to_string(),
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_chain_non_terminating_at_end() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    Non-terminating Transform DebugPrinter named "debug-3" is last in chain. Last Transform must be terminating.
"#;

        let error = run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-2".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-3".to_string(),
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_chain_terminating_middle_non_terminating_at_end() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    Terminating Transform NullSink named "sink" is not last in chain. Terminating Transform must be last in chain.
    Non-terminating Transform DebugPrinter named "debug-3" is last in chain. Last Transform must be terminating.
"#;

        let error = run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-2".to_string(),
            }),
            Box::new(NullSinkConfig {
                name: "sink".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-3".to_string(),
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_chain_valid_subchain_cassandra_valkey_cache() {
        let caching_schema = HashMap::new();

        run_test_topology_cassandra(vec![
            Box::new(DebugPrinterConfig {
                name: "debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-2".to_string(),
            }),
            Box::new(ValkeyCacheConfig {
                name: "cache".to_string(),
                chain: TransformChainConfig(vec![
                    Box::new(DebugPrinterConfig {
                        name: "c-debug-1".to_string(),
                    }),
                    Box::new(DebugPrinterConfig {
                        name: "c-debug-2".to_string(),
                    }),
                    Box::new(NullSinkConfig {
                        name: "c-sink".to_string(),
                    }),
                ]),
                caching_schema,
            }),
            Box::new(NullSinkConfig {
                name: "sink".to_string(),
            }),
        ])
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_validate_chain_invalid_subchain_cassandra_valkey_cache() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    ValkeyCache:
      cache chain:
        Terminating Transform NullSink named "c-sink-1" is not last in chain. Terminating Transform must be last in chain.
"#;

        let error = run_test_topology_cassandra(vec![
            Box::new(DebugPrinterConfig {
                name: "debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-2".to_string(),
            }),
            Box::new(ValkeyCacheConfig {
                name: "cache".to_string(),
                chain: TransformChainConfig(vec![
                    Box::new(DebugPrinterConfig {
                        name: "c-debug".to_string(),
                    }),
                    Box::new(NullSinkConfig {
                        name: "c-sink-1".to_string(),
                    }),
                    Box::new(DebugPrinterConfig {
                        name: "c-debug-2".to_string(),
                    }),
                    Box::new(NullSinkConfig {
                        name: "c-sink-2".to_string(),
                    }),
                ]),
                caching_schema: HashMap::new(),
            }),
            Box::new(NullSinkConfig {
                name: "sink".to_string(),
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_chain_valid_subchain_parallel_map() {
        run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-2".to_string(),
            }),
            Box::new(ParallelMapConfig {
                name: "pmap".to_string(),
                parallelism: 1,
                chain: TransformChainConfig(vec![
                    Box::new(DebugPrinterConfig {
                        name: "p-debug-1".to_string(),
                    }),
                    Box::new(DebugPrinterConfig {
                        name: "p-debug-2".to_string(),
                    }),
                    Box::new(NullSinkConfig {
                        name: "p-sink".to_string(),
                    }),
                ]),
                ordered_results: false,
            }),
        ])
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_validate_chain_invalid_subchain_parallel_map() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    ParallelMap:
      pmap[0] chain:
        Terminating Transform NullSink named "p-sink-1" is not last in chain. Terminating Transform must be last in chain.
"#;

        let error = run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-2".to_string(),
            }),
            Box::new(ParallelMapConfig {
                name: "pmap".to_string(),
                parallelism: 1,
                chain: TransformChainConfig(vec![
                    Box::new(DebugPrinterConfig {
                        name: "p-debug".to_string(),
                    }),
                    Box::new(NullSinkConfig {
                        name: "p-sink-1".to_string(),
                    }),
                    Box::new(DebugPrinterConfig {
                        name: "p-debug-2".to_string(),
                    }),
                    Box::new(NullSinkConfig {
                        name: "p-sink-2".to_string(),
                    }),
                ]),
                ordered_results: false,
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_chain_subchain_terminating_in_middle() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    ParallelMap:
      pmap[0] chain:
        Terminating Transform NullSink named "p-sink-1" is not last in chain. Terminating Transform must be last in chain.
"#;

        let subchain = TransformChainConfig(vec![
            Box::new(DebugPrinterConfig {
                name: "p-debug".to_string(),
            }),
            Box::new(NullSinkConfig {
                name: "p-sink-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "p-debug-2".to_string(),
            }),
            Box::new(NullSinkConfig {
                name: "p-sink-2".to_string(),
            }),
        ]);

        let error = run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-2".to_string(),
            }),
            Box::new(ParallelMapConfig {
                name: "pmap".to_string(),
                parallelism: 1,
                chain: subchain,
                ordered_results: true,
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_chain_subchain_non_terminating_at_end() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    ParallelMap:
      pmap[0] chain:
        Non-terminating Transform DebugPrinter named "p-debug-2" is last in chain. Last Transform must be terminating.
"#;

        let subchain = TransformChainConfig(vec![
            Box::new(DebugPrinterConfig {
                name: "p-debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "p-debug-2".to_string(),
            }),
        ]);

        let error = run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-2".to_string(),
            }),
            Box::new(ParallelMapConfig {
                name: "pmap".to_string(),
                parallelism: 1,
                chain: subchain,
                ordered_results: true,
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_chain_subchain_terminating_middle_non_terminating_at_end() {
        let expected = r#"Topology errors
foo source:
  foo chain:
    ParallelMap:
      pmap[0] chain:
        Terminating Transform NullSink named "p-sink" is not last in chain. Terminating Transform must be last in chain.
        Non-terminating Transform DebugPrinter named "p-debug-2" is last in chain. Last Transform must be terminating.
"#;

        let subchain = TransformChainConfig(vec![
            Box::new(DebugPrinterConfig {
                name: "p-debug-1".to_string(),
            }),
            Box::new(NullSinkConfig {
                name: "p-sink".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "p-debug-2".to_string(),
            }),
        ]);

        let error = run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "debug-1".to_string(),
            }),
            Box::new(DebugPrinterConfig {
                name: "debug-2".to_string(),
            }),
            Box::new(ParallelMapConfig {
                name: "pmap".to_string(),
                parallelism: 1,
                chain: subchain,
                ordered_results: true,
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_repeated_source_names() {
        let expected = r#"Topology errors
Duplicate source names detected:
  "foo" used by:
    source[0] "foo"
    source[1] "foo"
Duplicate chain names detected:
  "foo" used by:
    root chain for source[0] "foo"
    root chain for source[1] "foo"
"#;

        let mut sources = create_source_from_chain_valkey(vec![Box::new(NullSinkConfig {
            name: "sink".to_string(),
        })]);
        sources.extend(create_source_from_chain_valkey(vec![Box::new(
            NullSinkConfig {
                name: "sink1".to_string(),
            },
        )]));

        let topology = Topology { sources };
        let (_sender, trigger_shutdown_rx) = watch::channel::<bool>(false);
        let error = topology
            .run_chains(trigger_shutdown_rx, HashMap::new())
            .await
            .unwrap_err()
            .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_repeated_transform_names() {
        let expected = r#"Topology errors
Duplicate transform names detected:
  "dup" used by:
    Transform[0] DebugPrinter named "dup" in source[0] "foo" chain "foo"
    Transform[1] NullSink named "dup" in source[0] "foo" chain "foo"
"#;

        let error = run_test_topology_valkey(vec![
            Box::new(DebugPrinterConfig {
                name: "dup".to_string(),
            }),
            Box::new(NullSinkConfig {
                name: "dup".to_string(),
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_duplicate_chain_names_user_defined() {
        // Tee's main chain is named after the transform, so a Tee named "foo" creates chain "foo" which duplicates the root chain "foo".
        let expected = r#"Topology errors
Duplicate chain names detected:
  "foo" used by:
    root chain for source[0] "foo"
    chain "foo" at source[0] "foo" chain "foo" -> subchain "foo" (from Transform Tee named "foo")
"#;

        let error = run_test_topology_valkey(vec![
            Box::new(TeeConfig {
                name: "foo".to_string(),
                behavior: None,
                timeout_micros: None,
                chain: TransformChainConfig(vec![Box::new(NullSinkConfig {
                    name: "tee-sink".to_string(),
                })]),
                buffer_size: None,
                switch_port: None,
            }),
            Box::new(NullSinkConfig {
                name: "sink".to_string(),
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_duplicate_chain_names_auto_derived() {
        let expected = r#"Topology errors
Duplicate chain names detected:
  "foo" used by:
    root chain for source[0] "foo"
    chain "foo" at source[0] "foo" chain "foo" -> subchain "foo" (from Transform ValkeyCache named "foo")
"#;

        let error = run_test_topology_cassandra(vec![
            Box::new(ValkeyCacheConfig {
                name: "foo".to_string(),
                chain: TransformChainConfig(vec![Box::new(NullSinkConfig {
                    name: "cache-sink".to_string(),
                })]),
                caching_schema: HashMap::new(),
            }),
            Box::new(NullSinkConfig {
                name: "sink".to_string(),
            }),
        ])
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn test_validate_subchain_on_mismatch_derived_chain_name() {
        // SubchainOnMismatch chain name is derived as <tee-name>.mismatch; two Tees get distinct chain names.
        run_test_topology_valkey(vec![
            Box::new(TeeConfig {
                name: "tee-a".to_string(),
                behavior: Some(ConsistencyBehaviorConfig::SubchainOnMismatch {
                    chain: TransformChainConfig(vec![Box::new(NullSinkConfig {
                        name: "mismatch-sink-a".to_string(),
                    })]),
                }),
                timeout_micros: None,
                chain: TransformChainConfig(vec![Box::new(NullSinkConfig {
                    name: "tee-a-sink".to_string(),
                })]),
                buffer_size: None,
                switch_port: None,
            }),
            Box::new(TeeConfig {
                name: "tee-b".to_string(),
                behavior: Some(ConsistencyBehaviorConfig::SubchainOnMismatch {
                    chain: TransformChainConfig(vec![Box::new(NullSinkConfig {
                        name: "mismatch-sink-b".to_string(),
                    })]),
                }),
                timeout_micros: None,
                chain: TransformChainConfig(vec![Box::new(NullSinkConfig {
                    name: "tee-b-sink".to_string(),
                })]),
                buffer_size: None,
                switch_port: None,
            }),
            Box::new(NullSinkConfig {
                name: "sink".to_string(),
            }),
        ])
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_validate_chain_multiple_subchains() {
        let (_sender, trigger_shutdown_rx) = watch::channel::<bool>(false);

        let topology =
            Topology::from_file("../shotover-proxy/tests/test-configs/invalid_subchains.yaml")
                .unwrap();
        let error = topology
            .run_chains(trigger_shutdown_rx, HashMap::new())
            .await
            .unwrap_err()
            .to_string();

        let expected = r#"Topology errors
valkey1 source:
  valkey1 chain:
    Terminating Transform NullSink named "sink-1" is not last in chain. Terminating Transform must be last in chain.
    Terminating Transform NullSink named "sink-2" is not last in chain. Terminating Transform must be last in chain.
    Non-terminating Transform DebugPrinter named "debug" is last in chain. Last Transform must be terminating.
valkey2 source:
  valkey2 chain:
    ParallelMap:
      pmap[0] chain:
        Terminating Transform NullSink named "p-sink" is not last in chain. Terminating Transform must be last in chain.
        Non-terminating Transform DebugPrinter named "p-debug" is last in chain. Last Transform must be terminating.
"#;

        assert_eq!(error, expected);
    }
}

#[cfg(all(test, feature = "postgres", feature = "alpha-transforms"))]
mod partial_response_validation_tests {
    use super::{chain_emits_partial_responses, collect_partial_response_errors};
    use crate::config::chain::TransformChainConfig;

    /// Parses a chain exactly as a topology file would, so these exercise the real config surface
    /// — typetag dispatch and `deny_unknown_fields` — rather than hand-built config objects.
    fn chain(yaml: &str) -> TransformChainConfig {
        let deserializer = serde_yaml::Deserializer::from_str(yaml);
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap()
    }

    fn errors(yaml: &str) -> Vec<String> {
        let mut errors = vec![];
        collect_partial_response_errors(&chain(yaml), "test chain", &mut errors);
        errors
    }

    const REDACT_THEN_STREAMING_SINK: &str = r#"
- PostgresRedactColumn:
    name: "redact"
    column: "secret"
    replacement: "***"
- PostgresSinkSingle:
    name: "sink"
    remote_address: "127.0.0.1:5432"
    connect_timeout_ms: 3000
    stream_threshold_bytes: 1048576
"#;

    const REDACT_THEN_WHOLE_TRAIN_SINK: &str = r#"
- PostgresRedactColumn:
    name: "redact"
    column: "secret"
    replacement: "***"
- PostgresSinkSingle:
    name: "sink"
    remote_address: "127.0.0.1:5432"
    connect_timeout_ms: 3000
"#;

    const STREAMING_SINK_ONLY: &str = r#"
- PostgresSinkSingle:
    name: "sink"
    remote_address: "127.0.0.1:5432"
    connect_timeout_ms: 3000
    stream_threshold_bytes: 1048576
"#;

    /// A chunking sink plus a transform that needs whole trains is refused, and the error names the
    /// transform and says how to fix it.
    #[test]
    fn refuses_streaming_chain_containing_redaction() {
        let errors = errors(REDACT_THEN_STREAMING_SINK);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("PostgresRedactColumn"), "{}", errors[0]);
        assert!(errors[0].contains(r#""redact""#), "{}", errors[0]);
        assert!(
            errors[0].contains("stream_threshold_bytes: 0"),
            "{}",
            errors[0]
        );
    }

    /// The same chain with streaming off is accepted. `stream_threshold_bytes` defaults to 0, so no
    /// topology that starts today can begin failing because of this validation.
    #[test]
    fn accepts_the_same_chain_with_streaming_off() {
        assert!(!chain_emits_partial_responses(&chain(
            REDACT_THEN_WHOLE_TRAIN_SINK
        )));
        assert!(errors(REDACT_THEN_WHOLE_TRAIN_SINK).is_empty());
    }

    /// A chunking sink on its own is fine: it both emits partials and accepts them.
    #[test]
    fn accepts_a_streaming_sink_on_its_own() {
        assert!(chain_emits_partial_responses(&chain(STREAMING_SINK_ONLY)));
        assert!(errors(STREAMING_SINK_ONLY).is_empty());
    }

    /// A Tee whose SUB-chain streams is refused even though the Tee's own chain does not: the
    /// sub-chain's responses come back to the Tee, which compares whole trains and cannot line up
    /// chunk boundaries that differ per chain.
    #[test]
    fn refuses_tee_whose_subchain_streams() {
        let yaml = r#"
- Tee:
    name: "tee"
    chain:
      - PostgresSinkSingle:
          name: "teed-sink"
          remote_address: "127.0.0.1:5432"
          connect_timeout_ms: 3000
          stream_threshold_bytes: 1048576
- PostgresSinkSingle:
    name: "sink"
    remote_address: "127.0.0.1:5432"
    connect_timeout_ms: 3000
"#;
        let errors = errors(yaml);
        assert!(
            errors.iter().any(|e| e.contains("Tee")),
            "expected the Tee to be named: {errors:?}"
        );
    }
}
