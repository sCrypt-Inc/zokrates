use crate::constants;
use crate::helpers::*;
use crate::ops::generate_key_proof::deserialize;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::path::PathBuf;
use zokrates_field::{Field, Secp256k1Field};
use zokrates_core::flat_absy::{FlatProg, FlatExpression, FlatStatement };
use zokrates_core::pederson::{Pedersen, GateProof};


pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("verify-key-proof")
        .about("Verifies a given proof")
        .arg(
            Arg::with_name("proof-path")
                .short("j")
                .long("proof-path")
                .help("Path of the JSON proof file")
                .value_name("FILE")
                .takes_value(true)
                .required(true)
                .default_value(constants::JSON_PROOF_PATH),
        )
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .help("Path of the circuit")
                .value_name("FILE")
                .takes_value(true)
                .required(true)
                .default_value(constants::FLATTENED_PATH),
        )
        .arg(
            Arg::with_name("pubkey")
                .short("p")
                .long("pubkey")
                .help("Public key of the secret key")
                .value_name("PublicKey")
                .takes_value(true)
                .required(true)
        )
}

pub fn exec(sub_matches: &ArgMatches) -> Result<(), String> {
    cli_verify(sub_matches)
}

fn cli_verify(sub_matches: &ArgMatches) -> Result<(), String> {
    println!("Performing verification...");
    let path = PathBuf::from(sub_matches.value_of("input").unwrap());

    let file = File::open(path.clone())
        .map_err(|why| format!("Could not open {}: {}", path.display(), why))?;

    let mut reader = BufReader::new(file);
    let mut source = String::new();
    reader.read_to_string(&mut source).unwrap();

    let flatprog: FlatProg<Secp256k1Field> = deserialize(source).unwrap();

    let proof_path = Path::new(sub_matches.value_of("proof-path").unwrap());
    let proof_file = File::open(&proof_path)
        .map_err(|why| format!("Could not open {}: {}", proof_path.display(), why))?;

    let proof_reader = BufReader::new(proof_file);
    let proofs:Vec<GateProof> = serde_json::from_reader(proof_reader)
        .map_err(|why| format!("Could not deserialize proof: {}", why))?;

    let pedersen = Pedersen::new();


    let check_proof = |proof: &GateProof, expr| {
        match expr {
            FlatExpression::Number(_) =>  {

                assert!(proof.is_mul_gate());
            },
            FlatExpression::Identifier(_) => {
                assert!(proof.is_mul_gate());
            },
            FlatExpression::Add(_, _) => {
                assert!(proof.is_add_gate());
            },
            FlatExpression::Mult(_, _) => {
                assert!(proof.is_mul_gate());
            }
            FlatExpression::Sub(_, _) => panic!("There must not be subtraction in the circuit."),
        };
    };

    let mut index = 0;
    let mut public_keys_vec: Vec<String> = vec![];
    for statement in &flatprog.main.statements {
        match statement {
            FlatStatement::Definition(_, expr) => {
                let proof: GateProof = proofs[index].clone();
                
                check_proof(&proof, expr.clone());

                pedersen.verify_proof::<Secp256k1Field>(&proof);

                if proof.has_opening_key() {
                    let public_keys = proof.opening_public_keys();
                    public_keys_vec.extend(public_keys.iter().cloned());
                }


                index += 1;
            }
            FlatStatement::Condition(_, expr, _) => {
                let proof = proofs[index].clone();
                check_proof(&proof, expr.clone());
                pedersen.verify_proof::<Secp256k1Field>(&proof);

                if proof.has_opening_key() {
                    let public_keys = proof.opening_public_keys();
                    public_keys_vec.extend(public_keys.iter().cloned());
                }

                index += 1;
            }
            _ => (),
        }
    }

    println!("total gates:  {}...", index);
    let pubkey = String::from(sub_matches.value_of("pubkey").unwrap());

    let success = pedersen.verify_public_key(pubkey.as_str(), &public_keys_vec);

    if success {
        println!("Private key corresponding to public key {} hashes to {}", pubkey, "todo");
    } else {
        println!("Private key corresponding to public key {} does not hash to {}", pubkey, "todo");
    }

    Ok(())
}
