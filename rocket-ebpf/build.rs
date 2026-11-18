use anyhow::{anyhow, Context as _};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "rocket-ebpf-ebpf")
        .ok_or_else(|| anyhow!("rocket-ebpf-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_features: &[&str] = if std::env::var_os("CARGO_FEATURE_ORIN_R36_RT").is_some() {
        &["orin-r36-rt"]
    } else {
        &[]
    };
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        features: ebpf_features,
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
