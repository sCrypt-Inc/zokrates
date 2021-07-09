use crate::constants;
use crate::helpers::CurveParameter;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use zokrates_core::compile::{deserialize, CompilationArtifacts, CompileConfig, CompileError};
use zokrates_field::{Bls12_377Field, Bls12_381Field, Bn128Field, Bw6_761Field, Field};

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("deserialize")
        .about("deserialize into flattened conditions.")
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .help("Path of the flattened conditions")
            .value_name("FILE")
            .takes_value(true)
            .required(true)
        ).arg(Arg::with_name("stdlib-path")
        .long("stdlib-path")
        .help("Path to the standard library")
        .value_name("PATH")
        .takes_value(true)
        .required(false)
        .env("ZOKRATES_STDLIB")
        .default_value(constants::DEFAULT_STDLIB_PATH.as_str())
    ).arg(Arg::with_name("curve")
        .short("c")
        .long("curve")
        .help("Curve to be used in the compilation")
        .takes_value(true)
        .required(false)
        .possible_values(constants::CURVES)
        .default_value(constants::BN128)
    )
}

pub fn exec(sub_matches: &ArgMatches) -> Result<(), String> {
    let curve = CurveParameter::try_from(sub_matches.value_of("curve").unwrap())?;
    match curve {
        CurveParameter::Bn128 => cli_deserialize::<Bn128Field>(sub_matches),
        CurveParameter::Bls12_377 => cli_deserialize::<Bls12_377Field>(sub_matches),
        CurveParameter::Bls12_381 => cli_deserialize::<Bls12_381Field>(sub_matches),
        CurveParameter::Bw6_761 => cli_deserialize::<Bw6_761Field>(sub_matches),
    }
}

fn cli_deserialize<T: Field>(sub_matches: &ArgMatches) -> Result<(), String> {

    println!("Deserializing {}\n", sub_matches.value_of("input").unwrap());
    let path = PathBuf::from(sub_matches.value_of("input").unwrap());
   

    let file = File::open(path.clone())
        .map_err(|why| format!("Could not open {}: {}", path.display(), why))?;

    let mut reader = BufReader::new(file);
    let mut source = String::new();
    reader.read_to_string(&mut source).unwrap();

    let config = CompileConfig::default()
        .allow_unconstrained_variables(sub_matches.is_present("allow-unconstrained-variables"))
        .isolate_branches(sub_matches.is_present("isolate-branches"));

    let artifacts: CompilationArtifacts<T> = deserialize(source, &config)
    .map_err(|e| {
        format!(
            "Deserializing failed:\n {}", e
        )
    })?;


    //NOW we got flatprog 

    let flatprog =  artifacts.flatprog();

    println!("NOW we got flatprog : {}", flatprog);

    Ok(())
}
