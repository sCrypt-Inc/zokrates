use crate::cli_constants;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
#[cfg(feature = "ark")]
use zokrates_ark::Ark;
#[cfg(feature = "bellman")]
use zokrates_bellman::Bellman;
use zokrates_common::constants;
use zokrates_common::helpers::{CurveParameter, Parameters, SchemeParameter, BackendParameter};
use zokrates_field::{Bls12_377Field, Bls12_381Field, Bn128Field, Bw6_761Field, Field};
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
            Arg::with_name("output")
                .short("o")
                .long("output")
                .help("Path of the output file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(cli_constants::VERIFICATION_SCRYPT_CONTRACT_DEFAULT_PATH),
        )
        .arg(
            Arg::with_name("backend")
                .short("b")
                .long("backend")
                .help("Backend to use")
                .takes_value(true)
                .required(false)
                .possible_values(cli_constants::BACKENDS)
                .default_value(constants::ARK),
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

    let scheme = vk_scheme;
    let curve = vk_curve;

    // determine parameters based on that
    let parameters =
        Parameters::try_from((sub_matches.value_of("backend").unwrap(), curve, scheme))?;

    let alpha_g1_beta_g2 = match parameters {
        #[cfg(feature = "bellman")]
        Parameters(BackendParameter::Bellman, CurveParameter::Bn128, SchemeParameter::G16) => {
            get_miller_beta_alpha_string::<Bn128Field, G16, Bellman>(&vk)
        }
        #[cfg(feature = "bellman")]
        Parameters(BackendParameter::Bellman, CurveParameter::Bls12_381, SchemeParameter::G16) => {
            get_miller_beta_alpha_string::<Bls12_381Field, G16, Bellman>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bn128, SchemeParameter::G16) => {
            get_miller_beta_alpha_string::<Bn128Field, G16, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bls12_381, SchemeParameter::G16) => {
            get_miller_beta_alpha_string::<Bls12_381Field, G16, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bls12_377, SchemeParameter::G16) => {
            get_miller_beta_alpha_string::<Bls12_377Field, G16, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bw6_761, SchemeParameter::G16) => {
            get_miller_beta_alpha_string::<Bw6_761Field, G16, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bn128, SchemeParameter::GM17) => {
            get_miller_beta_alpha_string::<Bn128Field, GM17, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bls12_381, SchemeParameter::GM17) => {
            get_miller_beta_alpha_string::<Bls12_381Field, GM17, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bls12_377, SchemeParameter::GM17) => {
            get_miller_beta_alpha_string::<Bls12_377Field, GM17, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bw6_761, SchemeParameter::GM17) => {
            get_miller_beta_alpha_string::<Bw6_761Field, GM17, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bn128, SchemeParameter::MARLIN) => {
            get_miller_beta_alpha_string::<Bn128Field, Marlin, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bls12_381, SchemeParameter::MARLIN) => {
            get_miller_beta_alpha_string::<Bls12_381Field, Marlin, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bls12_377, SchemeParameter::MARLIN) => {
            get_miller_beta_alpha_string::<Bls12_377Field, Marlin, Ark>(&vk)
        }
        #[cfg(feature = "ark")]
        Parameters(BackendParameter::Ark, CurveParameter::Bw6_761, SchemeParameter::MARLIN) => {
            get_miller_beta_alpha_string::<Bw6_761Field, Marlin, Ark>(&vk)
        }
        _ => unreachable!(),
    };

    match (curve_parameter, scheme_parameter) {
        (CurveParameter::Bn128, SchemeParameter::G16) => {
            cli_export_verifier::<Bn128Field, G16>(sub_matches, vk, alpha_g1_beta_g2.unwrap())
        }
        (CurveParameter::Bn128, SchemeParameter::GM17) => {
            cli_export_verifier::<Bn128Field, GM17>(sub_matches, vk, alpha_g1_beta_g2.unwrap())
        }
        (CurveParameter::Bn128, SchemeParameter::MARLIN) => {
            cli_export_verifier::<Bn128Field, Marlin>(sub_matches, vk, alpha_g1_beta_g2.unwrap())
        }
        (curve_parameter, scheme_parameter) => Err(format!("Could not export verifier with given parameters (curve: {}, scheme: {}): not supported", curve_parameter, scheme_parameter))
    }
}

fn cli_export_verifier<T: ScryptCompatibleField, S: ScryptCompatibleScheme<T>>(
    sub_matches: &ArgMatches,
    vk: serde_json::Value,
    alpha_g1_beta_g2: String,
) -> Result<(), String> {
    println!("Exporting verifier...");

    let vk = serde_json::from_value(vk).map_err(|why| format!("{}", why))?;

    let verifier = S::export_scrypt_verifier(vk, alpha_g1_beta_g2);

    //write output file
    let output_path = Path::new(sub_matches.value_of("output").unwrap());
    let output_file = File::create(&output_path)
        .map_err(|why| format!("Could not create {}: {}", output_path.display(), why))?;

    let mut writer = BufWriter::new(output_file);

    writer
        .write_all(verifier.as_bytes())
        .map_err(|_| "Failed writing output to file".to_string())?;

    println!("Verifier exported to '{}'", output_path.display());
    Ok(())
}

fn get_miller_beta_alpha_string<T: Field, S: Scheme<T>, B: Backend<T, S>>(
    vk: &serde_json::Value,
) -> Result<String, String>  {

    let vk = serde_json::from_value(vk.clone())
    .map_err(|why| format!("Could not deserialize verification key: {}", why))?;
    
    Ok(B::get_miller_beta_alpha_string(vk))
}
