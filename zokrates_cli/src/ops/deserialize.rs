use crate::constants;
use crate::helpers::CurveParameter;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::path::PathBuf;
use zokrates_core::flat_absy::FlatProg;
use zokrates_core::ir;
use zokrates_field::{Bls12_377Field, Bls12_381Field, Bn128Field, Bw6_761Field, Field};

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("deserialize")
        .about("deserialize into flattened program.")
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .help("Path of the flattened program")
                .value_name("FILE")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("stdlib-path")
                .long("stdlib-path")
                .help("Path to the standard library")
                .value_name("PATH")
                .takes_value(true)
                .required(false)
                .env("ZOKRATES_STDLIB")
                .default_value(constants::DEFAULT_STDLIB_PATH.as_str()),
        )
        .arg(
            Arg::with_name("curve")
                .short("c")
                .long("curve")
                .help("Curve to be used in the compilation")
                .takes_value(true)
                .required(false)
                .possible_values(constants::CURVES)
                .default_value(constants::BN128),
        )
        .arg(
            Arg::with_name("witness")
                .short("w")
                .long("witness")
                .help("deserialize witness")
                .takes_value(false)
                .required(false),
        )
}

pub fn exec(sub_matches: &ArgMatches) -> Result<(), String> {
    let curve = CurveParameter::try_from(sub_matches.value_of("curve").unwrap())?;
    match curve {
        CurveParameter::Bn128 => {
            if sub_matches.is_present("witness") {
                cli_deserialize_witness::<Bn128Field>(sub_matches)
            } else {
                cli_deserialize::<Bn128Field>(sub_matches)
            }
        }
        CurveParameter::Bls12_377 => {
            if sub_matches.is_present("witness") {
                cli_deserialize_witness::<Bls12_377Field>(sub_matches)
            } else {
                cli_deserialize::<Bls12_377Field>(sub_matches)
            }
        }
        CurveParameter::Bls12_381 => {
            if sub_matches.is_present("witness") {
                cli_deserialize_witness::<Bls12_381Field>(sub_matches)
            } else {
                cli_deserialize::<Bls12_381Field>(sub_matches)
            }
        }

        CurveParameter::Bw6_761 => {
            if sub_matches.is_present("witness") {
                cli_deserialize_witness::<Bw6_761Field>(sub_matches)
            } else {
                cli_deserialize::<Bw6_761Field>(sub_matches)
            }
        }
    }
}

fn deserialize<T: Field>(source: String) -> Result<FlatProg<T>, serde_json::Error> {
    Ok(serde_json::from_str(&source).unwrap())
}

fn cli_deserialize<T: Field>(sub_matches: &ArgMatches) -> Result<(), String> {
    println!("Deserializing {}\n", sub_matches.value_of("input").unwrap());
    let path = PathBuf::from(sub_matches.value_of("input").unwrap());

    let file = File::open(path.clone())
        .map_err(|why| format!("Could not open {}: {}", path.display(), why))?;

    let mut reader = BufReader::new(file);
    let mut source = String::new();
    reader.read_to_string(&mut source).unwrap();

    let flatprog: FlatProg<T> = deserialize(source).unwrap();

    //NOW we got flatprog

    println!("NOW we got flatprog : {}", flatprog);

    Ok(())
}

fn cli_deserialize_witness<T: Field>(sub_matches: &ArgMatches) -> Result<(), String> {
    println!(
        "Deserializing witness {}\n",
        sub_matches.value_of("input").unwrap()
    );
    let witness_path = Path::new(sub_matches.value_of("input").unwrap());
    let witness_file = File::open(&witness_path)
        .map_err(|why| format!("Could not open {}: {}", witness_path.display(), why))?;

    let witness: ir::Witness<T> = ir::Witness::read(witness_file)
        .map_err(|why| format!("Could not load witness: {:?}", why))?;

    println!("witness csv len {}", witness.0.len());
    println!("now you can access any var in the witness");

    match witness.get("~out_0") {
        Some(out_0) => println!("~out_0: {}", out_0),
        None => println!("~out_0 is None."),
    }

    Ok(())
}
