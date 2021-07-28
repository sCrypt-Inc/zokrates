use crate::constants;
use crate::helpers::CurveParameter;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::path::PathBuf;
use zokrates_core::flat_absy::{FlatProg, FlatExpression, FlatStatement };
use zokrates_core::ir::{self, Witness};
use zokrates_field::{Bls12_377Field, Bls12_381Field, Bn128Field, Bw6_761Field, Field, Secp256k1Field};

use zokrates_core::pederson::{Pedersen, GateProof};

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("generate-key-proof")
        .about("Calculates proof for a key statement")
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .help("Path of the flattened program")
                .value_name("FILE")
                .takes_value(true)
                .required(true)
                .default_value(constants::FLATTENED_PATH),
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
            Arg::with_name("witness")
                .short("w")
                .long("witness")
                .help("Path of the witness file")
                .takes_value(true)
                .value_name("WITNESS_FILE")
                .required(true)
                .default_value(constants::WITNESS_DEFAULT_PATH),
        )        
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .help("Path of the output proof file")
                .takes_value(true)
                .value_name("OUTPUT_FILE")
                .required(true)
                .default_value(constants::JSON_PROOF_PATH),
        )
}

pub fn exec(sub_matches: &ArgMatches) -> Result<(), String> {
    cli_generate_key_proof::<Secp256k1Field>(sub_matches)
}

pub fn deserialize<T: Field>(source: String) -> Result<FlatProg<T>, serde_json::Error> {
    Ok(serde_json::from_str(&source).unwrap())
}


pub fn private_inputs_ids<T: Field>(flatprog: &FlatProg<T>) -> Vec<usize> {
    flatprog.main.arguments.iter().filter_map(|p| match p.private { 
        true => Some(p.id.id()),
        false => None
     }).collect()
}


fn cli_generate_key_proof<T: Field>(sub_matches: &ArgMatches) -> Result<(), String> {
    println!("Generating proofs for {}\n", sub_matches.value_of("input").unwrap());
    let path = PathBuf::from(sub_matches.value_of("input").unwrap());

    let file = File::open(path.clone())
        .map_err(|why| format!("Could not open {}: {}", path.display(), why))?;

    let mut reader = BufReader::new(file);
    let mut source = String::new();
    reader.read_to_string(&mut source).unwrap();

    let flatprog: FlatProg<T> = deserialize(source).unwrap();


    let witness = deserialize_witness::<T>(sub_matches).unwrap();
    

    let private_inputs = private_inputs_ids::<T>(&flatprog);


    let fetch_expr_value_closure =  |a: &Box<FlatExpression<T>>, b: &Box<FlatExpression<T>>| {
        let a_value = match a.as_ref() {
            FlatExpression::Number(v) => v,
            FlatExpression::Identifier(v) => witness.getvariable(v).unwrap(),
            _ => {
                panic!("unknown definition");
            }
        };

        let b_value = match b.as_ref() {
            FlatExpression::Number(v) => v,
            FlatExpression::Identifier(v) => witness.getvariable(v).unwrap(),
            _ => {
                panic!("unknown definition");
            }
        };

        (a_value.clone(), b_value.clone())
    };

    let fetch_opening_closure =  |a: &Box<FlatExpression<T>>, b: &Box<FlatExpression<T>>| {
        let is_a_opening_key = match a.as_ref() {
            FlatExpression::Identifier(v) => private_inputs.contains(&v.id()),
            _ => false
        };

        let is_b_opening_key = match b.as_ref() {
            FlatExpression::Identifier(v) => private_inputs.contains(&v.id()),
            _ => false
        };


        let mut opening_key_indexs = None;
        if is_a_opening_key || is_b_opening_key {
            let mut indexs = vec![];
            if is_a_opening_key {
                indexs.push(0);
            }

            if is_b_opening_key {
                indexs.push(1);
            } 
            opening_key_indexs = Some(indexs);
        }

        opening_key_indexs
    };

    let pedersen = Pedersen::new();
    let mut proofs: Vec<GateProof> = vec![];
    for statement in &flatprog.main.statements {
       

        match statement {
            
            FlatStatement::Definition(variable, expr) => {
                
                
                let value_o = witness.getvariable(variable).unwrap().clone();

                let prover = match expr {
                    FlatExpression::Number(v) =>  {

                        pedersen.generate_mul_prover(T::from(1), v.clone(), value_o, None)
                    },
                    FlatExpression::Identifier(v) => {
                        let v = witness.getvariable(v).unwrap().clone();

                        pedersen.generate_mul_prover(T::from(1), v.clone(), value_o, None)
                    },
                    FlatExpression::Add(a, b) => {
                        let (a_value,b_value ) = fetch_expr_value_closure(a, b);
                        let opening_key_indexs = fetch_opening_closure(a, b);
  
                        pedersen.generate_add_prover(a_value, b_value, value_o, opening_key_indexs)

                    },
                    FlatExpression::Mult(a, b) => {
                        let (a_value,b_value ) = fetch_expr_value_closure(a, b);
                        let opening_key_indexs = fetch_opening_closure(a, b);
                        pedersen.generate_mul_prover(a_value, b_value, value_o, opening_key_indexs)
                    }
                    FlatExpression::Sub(_, _) => panic!("There must NOT be Sub expr in FlatProg."),

                };

                let success = pedersen.verify_prover::<T>(&prover);

                if !success {
                    println!("definition fail variable: {:?}, expr: {:?}", variable, expr);
                    panic!("definition fail");
                }

                let proof = pedersen.generate_proof::<T>(&prover);

                proofs.push(proof);

            },
            FlatStatement::Condition(expr1, expr2, _) => {
                
                let value_o = match expr1 {
                    FlatExpression::Number(v) => v.clone(),
                    FlatExpression::Identifier(v) => witness.getvariable(v).unwrap().clone(),
                    _ => panic!("There must NOT be expr in here."),

                };

                let prover = match expr2 {
                    FlatExpression::Number(v) =>  {

                        pedersen.generate_mul_prover(T::from(1), v.clone(), value_o, None)
                    },
                    FlatExpression::Identifier(v) => {
                        let v = witness.getvariable(v).unwrap().clone();

                        pedersen.generate_mul_prover(T::from(1), v.clone(), value_o, None)
                    },
                    FlatExpression::Add(a, b) => {
                        let (a_value,b_value ) = fetch_expr_value_closure(a, b);
                        let opening_key_indexs = fetch_opening_closure(a, b);
                        pedersen.generate_add_prover(a_value, b_value, value_o, opening_key_indexs)
                    },
                    FlatExpression::Mult(a, b) => {
                        let (a_value,b_value ) = fetch_expr_value_closure(a, b);
                        let opening_key_indexs = fetch_opening_closure(a, b);
                        pedersen.generate_mul_prover(a_value, b_value, value_o, opening_key_indexs )
                    }
                    FlatExpression::Sub(_, _) => panic!("There must NOT be Sub expr in FlatProg."),

                };

                let success = pedersen.verify_prover::<T>(&prover);

                if !success {
                    println!("condition fail expr1: {:?}, expr2: {:?}", expr1, expr2);
                    panic!("condition fail");
                }

                let proof = pedersen.generate_proof::<T>(&prover);

                proofs.push(proof);

            },
            _ => (),

        }
    }

    println!("proofs len {}", proofs.len());

    let proofs_path = PathBuf::from(sub_matches.value_of("output").unwrap());

    let proofs_file = File::create(&proofs_path)
    .map_err(|why| format!("Could not create {}: {}", proofs_path.display(), why))?;

    let result = serde_json::to_writer_pretty(std::io::BufWriter::new(proofs_file), &proofs);


    match result {
        Ok(_) => println!("Output to proof.json"),
        _ => panic!("generate proof fail")
    }

    Ok(())
}

fn deserialize_witness<T: Field>(sub_matches: &ArgMatches) -> Result<ir::Witness<T>, String> {

    let witness_path = Path::new(sub_matches.value_of("input").unwrap()).with_file_name("witness");
    let witness_file = File::open(&witness_path)
        .map_err(|why| format!("Could not open {}: {}", witness_path.display(), why))?;

    let witness: ir::Witness<T> = ir::Witness::read(witness_file)
        .map_err(|why| format!("Could not load witness: {:?}", why))?;

    Ok(witness)
}
