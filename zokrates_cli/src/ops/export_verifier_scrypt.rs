use crate::cli_constants;
use clap::{App, Arg, ArgMatches, SubCommand};
use include_dir::{include_dir, Dir};
use std::convert::TryFrom;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::process;
use zokrates_common::constants;
use zokrates_common::helpers::{CurveParameter, SchemeParameter};
use zokrates_field::{Bls12_381Field, Bn128Field};
use zokrates_proof_systems::*;

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("export-verifier-scrypt")
        .about("Exports a verifier as sCrypt smart contract")
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .help("Path of the verification key")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(cli_constants::VERIFICATION_KEY_DEFAULT_PATH),
        )
        .arg(
            Arg::with_name("backend")
                .short("b")
                .long("backend")
                .help("Backend to use")
                .takes_value(true)
                .required(false)
                .possible_values(cli_constants::BACKENDS)
                .default_value(constants::BELLMAN),
        )
}

pub fn exec(sub_matches: &ArgMatches) -> Result<(), String> {
    let vk_path = Path::new(sub_matches.value_of("input").unwrap());
    let vk_file = File::open(&vk_path)
        .map_err(|why| format!("Could not open {}: {}", vk_path.display(), why))?;

    // deserialize vk to JSON
    let vk_reader = BufReader::new(vk_file);
    let vk: serde_json::Value = serde_json::from_reader(vk_reader)
        .map_err(|why| format!("Could not deserialize verification key: {}", why))?;

    // extract curve and scheme parameters
    let vk_curve = vk
        .get("curve")
        .ok_or_else(|| "Field `curve` not found in verification key".to_string())?
        .as_str()
        .ok_or_else(|| "`curve` should be a string".to_string())?;
    let vk_scheme = vk
        .get("scheme")
        .ok_or_else(|| "Field `scheme` not found in verification key".to_string())?
        .as_str()
        .ok_or_else(|| "`scheme` should be a string".to_string())?;

    let curve_parameter = CurveParameter::try_from(vk_curve)?;
    let scheme_parameter = SchemeParameter::try_from(vk_scheme)?;

    match (curve_parameter, scheme_parameter) {
        (CurveParameter::Bn128, SchemeParameter::G16) => {
            cli_export_verifier::<Bn128Field, G16>(vk, CurveParameter::Bn128)
        }
        (CurveParameter::Bn128, SchemeParameter::GM17) => {
            cli_export_verifier::<Bn128Field, GM17>(vk, CurveParameter::Bn128)
        }
        (CurveParameter::Bn128, SchemeParameter::MARLIN) => {
            cli_export_verifier::<Bn128Field, Marlin>(vk, CurveParameter::Bn128)
        }
        (CurveParameter::Bls12_381, SchemeParameter::G16) => {
            cli_export_verifier::<Bls12_381Field, G16>(vk, CurveParameter::Bls12_381)
        }
        (curve_parameter, scheme_parameter) => Err(format!("Could not export verifier with given parameters (curve: {}, scheme: {}): not supported", curve_parameter, scheme_parameter))
    }
}

fn cli_export_verifier<T: ScryptCompatibleField, S: ScryptCompatibleScheme<T>>(
    vk: serde_json::Value,
    curve_parameter: CurveParameter,
) -> Result<(), String> {
    println!("Exporting verifier...");

    let vk = serde_json::from_value(vk).map_err(|why| format!("{}", why))?;

    let verifier = S::export_scrypt_verifier(vk, curve_parameter);

    static PROJECT_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR");
    let scrypt_proj_template = PROJECT_DIR.get_dir("scrypt_proj_template/").unwrap();

    if let Err(e) = fs::remove_dir_all("scrypt_proj_template") {
        println!("Project template not present.");
    }

    if let Err(e) = fs::remove_dir_all("verifier") {
        println!("Verifier dir not present.");
    }

    if let Err(e) = fs::create_dir("scrypt_proj_template") {
        eprintln!("Failed to create empty verifier dir: {e}");
        process::exit(1);
    }
    if let Err(e) = scrypt_proj_template.extract("") {
        eprintln!("Failed extracting verifier dir: {e}");
        process::exit(1);
    }
    if let Err(e) = fs::rename("scrypt_proj_template", "verifier") {
        eprintln!("Failed to rename verifier dir: {e}");
        process::exit(1);
    }

    // Write output files
    let output_path = Path::new("verifier/src/contracts/snark.ts");
    let output_file = File::create(&output_path)
        .map_err(|why| format!("Could not create {}: {}", output_path.display(), why))?;
    let mut writer = BufWriter::new(output_file);
    writer
        .write_all(verifier.as_bytes())
        .map_err(|_| "Failed writing output to file".to_string())?;

    println!("Verifier code along with scaffolding exported to 'verifier' dir.");
    println!("Initialize the repo: cd verifier && git init && npm i");
    Ok(())
}
