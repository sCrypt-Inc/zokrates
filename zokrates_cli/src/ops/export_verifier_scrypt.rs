use crate::cli_constants;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use zokrates_common::helpers::{CurveParameter, SchemeParameter};
use zokrates_field::Bn128Field;
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
            cli_export_verifier::<Bn128Field, G16>(sub_matches, vk)
        }
        (CurveParameter::Bn128, SchemeParameter::GM17) => {
            cli_export_verifier::<Bn128Field, GM17>(sub_matches, vk)
        }
        (CurveParameter::Bn128, SchemeParameter::MARLIN) => {
            cli_export_verifier::<Bn128Field, Marlin>(sub_matches, vk)
        }
        (curve_parameter, scheme_parameter) => Err(format!("Could not export verifier with given parameters (curve: {}, scheme: {}): not supported", curve_parameter, scheme_parameter))
    }
}

fn cli_export_verifier<T: ScryptCompatibleField, S: ScryptCompatibleScheme<T>>(
    sub_matches: &ArgMatches,
    vk: serde_json::Value,
) -> Result<(), String> {
    println!("Exporting verifier...");

    let vk = serde_json::from_value(vk).map_err(|why| format!("{}", why))?;

    let verifier = S::export_scrypt_verifier(vk);

    //write output file
    let output_path = Path::new(sub_matches.value_of("output").unwrap());
    let output_file = File::create(&output_path)
        .map_err(|why| format!("Could not create {}: {}", output_path.display(), why))?;

    let mut writer = BufWriter::new(output_file);

    writer
        .write_all(verifier.as_bytes())
        .map_err(|_| "Failed writing output to file".to_string())?;




    let mut output_js_path = PathBuf::from(output_path.to_str().unwrap());
    output_js_path.set_extension("js");

    let output_js_file = File::create(&output_js_path)
    .map_err(|why| format!("Could not create {}: {}", output_js_path.display(), why))?;

    let mut writer = BufWriter::new(output_js_file);


    writer
    .write_all(JS_TEMPLATE.as_bytes())
    .map_err(|_| "Failed writing output to file".to_string())?;


    println!("Verifier exported to '{}', '{}'", output_path.display(), output_js_path.display());
    Ok(())
}



const JS_TEMPLATE: &str = r#"

const { buildContractClass, Int, buildTypeClasses, compileContractAsync, bsv } = require('scryptlib');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const axios = require('axios');
const { exit } = require('process');
const API_PREFIX = 'https://api.whatsonchain.com/v1/bsv/test'


// put your testnet privkey here.
const key = '';

if (!key) {
  genPrivKey()
}
const privateKey = new bsv.PrivateKey.fromWIF(key)


async function run() {

  const Verifier = buildContractClass(await compileContractAsync(path.join(__dirname, 'verifier.scrypt'), {
    out: __dirname,
    sourceMap: false,
    desc: false
  }));
  const { Proof, G1Point, G2Point, FQ2 } = buildTypeClasses(Verifier);
  verifier = new Verifier();

  const proof = JSON.parse(fs.readFileSync(path.join(__dirname, 'proof.json')));

  console.log("Proof: ");
  console.log(JSON.stringify(proof, null, 1));

  console.log("Simulate a verification call ...");

  const unlockCall = verifier.unlock(proof.inputs.map(input => new Int(input)),
    new Proof({
      a: new G1Point({
        x: new Int(proof.proof.a[0]),
        y: new Int(proof.proof.a[1]),
      }),
      b: new G2Point({
        x: new FQ2({
          x: new Int(proof.proof.b[0][1]),
          y: new Int(proof.proof.b[0][0]),
        }),
        y: new FQ2({
          x: new Int(proof.proof.b[1][1]),
          y: new Int(proof.proof.b[1][0]),
        })
      }),
      c: new G1Point({
        x: new Int(proof.proof.c[0]),
        y: new Int(proof.proof.c[1]),
      })
    })
  );

  const result = unlockCall.verify();

  assert.ok(result.success, result.error)

  console.log("Verification OK");

  console.log('start deploying zkSNARK verifier ... ')
  const tx = await deployContract(verifier, 10000);
  console.log('deployed txid:     ', tx.id)

  const unlockingTx = new bsv.Transaction();
  unlockingTx.addInput(createInputFromPrevTx(tx))
  .change(privateKey.toAddress())
  .setInputScript(0, (_) => {
      return unlockCall.toScript();
  })
  .seal()

  await sleep(10000);
  
  // unlock
  console.log('start calling zkSNARK verifier ... ')
  await sendTx(unlockingTx)

  console.log('unlocking txid:     ', unlockingTx.id)

  console.log('Succeeded on testnet')

}


run().then(() => {
  process.exit(0);
});





function genPrivKey() {
  const newPrivKey = new bsv.PrivateKey.fromRandom('testnet')
  console.log(`Missing private key, generating a new one ...
Private key generated: '${newPrivKey.toWIF()}'
You can fund its address '${newPrivKey.toAddress()}' from sCrypt faucet https://scrypt.io/#faucet`)
  exit(-1)
}



async function fetchUtxos(address) {
  let {
    data: utxos
  } = await axios.get(`${API_PREFIX}/address/${address}/unspent`)

  return utxos.map((utxo) => ({
    txId: utxo.tx_hash,
    outputIndex: utxo.tx_pos,
    satoshis: utxo.value,
    script: bsv.Script.buildPublicKeyHashOut(address).toHex(),
  }))
}



async function sendTx(tx) {
  const hex = tx.toString();

  try {

    const {
      data: txid
    } = await axios({
      method: 'post',
      url: `${API_PREFIX}/tx/raw`,
      data: {
        txhex: hex
      },
      maxBodyLength: Infinity
    });
      
    return txid
  } catch (error) {
    if (error.response && error.response.data === '66: insufficient priority') {
      throw new Error(`Rejected by miner. Transaction with fee is too low: expected Fee is ${expectedFee}, but got ${fee}, hex: ${hex}`)
    } else if (error.response) {
      throw new Error(error.response.data)
    } 

    console.error(error.response.data)
    throw error
  }
}

//create an input spending from prevTx's output, with empty script
function createInputFromPrevTx(tx, outputIndex) {
  const outputIdx = outputIndex || 0
  return new bsv.Transaction.Input({
    prevTxId: tx.id,
    outputIndex: outputIdx,
    script: new bsv.Script(), // placeholder
    output: tx.outputs[outputIdx]
  })
}

async function deployContract(contract, amount) {
  const address = privateKey.toAddress()
  const tx = new bsv.Transaction()
  
  tx.from(await fetchUtxos(address))
  .addOutput(new bsv.Transaction.Output({
    script: contract.lockingScript,
    satoshis: amount,
  }))
  .change(address)
  .sign(privateKey)

  await sendTx(tx)
  return tx
}

function sleep(time){
  return new Promise(function(resolve){
    setTimeout(resolve, time);
  });
}
"#;