use crate::constants;
use crate::helpers::CurveParameter;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{PathBuf};
use zokrates_field::{Bls12_377Field, Bls12_381Field, Bn128Field, Bw6_761Field, Field};
use zokrates_core::flat_absy::{FlatProg};

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("deserialize")
        .about("deserialize into flattened program.")
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .help("Path of the flattened program")
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


fn deserialize<T: Field>(
    source: String,
) -> Result<FlatProg<T>, serde_json::Error> {
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
