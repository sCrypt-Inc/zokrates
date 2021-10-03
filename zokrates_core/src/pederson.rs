use secp256k1zkp::{
    key, pedersen::Commitment, ContextFlag, PublicKey, Secp256k1, SecretKey,
};
use serde::{Deserialize, Serialize};
use zokrates_field::Field;
use rand_0_5::{thread_rng, Rng};

use sha2::{Sha256, Digest};
use lazy_static::lazy_static;

fn random_32_bytes<T: Field>() -> T {
    let mut rng = thread_rng();
    let mut ret = [0u8; 32];
    rng.fill(&mut ret);
    T::from_byte_vector(ret.to_vec())
}

lazy_static! {
    //let F = secp.commit_blind(key::ONE_KEY, key::ZERO_KEY).unwrap();
    pub static ref F: Commitment = Commitment::from_vec(vec![9, 80, 146, 155, 116, 193, 160, 73, 84, 183, 139, 75, 96, 53, 233, 122, 94, 7, 138, 90, 15, 40, 236, 150, 213, 71, 191, 238, 154, 206, 128, 58, 192]);
}


#[allow(non_snake_case)]
#[derive(Debug)]
pub struct PedersenWitness {
    W_L: Commitment,
    W_R: Commitment,
    W_O: Commitment,
}

#[derive(Debug, Clone)]
pub struct CommitAdd {
    r_b: SecretKey,
    b_commit: Commitment,
}

#[derive(Debug)]
pub struct CommitMul {
    t1: SecretKey,
    t2: SecretKey,
    t3: SecretKey,
    t4: SecretKey,
    t5: SecretKey,
    c1_commit: Commitment,
    c2_commit: Commitment,
    c3_commit: Commitment,
}

#[derive(Debug)]
pub struct Prover<T: Field> {
    r_l: SecretKey,
    r_r: SecretKey,
    r_o: SecretKey,
    value_l: T,
    value_r: T,
    value_o: T,
    witness: PedersenWitness,
    commit_add: Option<CommitAdd>,
    commit_mul: Option<CommitMul>,
    opening_key_indices: Option<Vec<usize>>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpeningKey {
    r: String,
    index: usize,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AddGateProof {
    z: String,
    b_commit: String,
    commits: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opening_keys: Option<Vec<OpeningKey>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MulGateProof {
    tuple:  (String, String, String, String, String),
    c_commits: Vec<String>,
    commits:Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opening_keys: Option<Vec<OpeningKey>>,
}

#[derive(Debug,Serialize, Deserialize, Clone)]
pub enum GateProof {
    AddGate(AddGateProof),
    MulGate(MulGateProof),
}






impl GateProof {
    pub fn is_add_gate(&self) -> bool {
        match self {
            GateProof::AddGate(_) => true,
            _ => false,
        }
    }
    pub fn is_mul_gate(&self) -> bool {
        match self {
            GateProof::MulGate(_) => true,
            _ => false,
        }
    }


    pub fn has_opening_key(&self) -> bool {
        match self {
            GateProof::MulGate(proof) => {
                proof.opening_keys.is_some()
            },
            GateProof::AddGate(proof) => {
                proof.opening_keys.is_some()
            },
        }
    }


    pub fn opening_public_keys(&self) -> Vec<String> {

        let opening = |commits: &Vec<String>, opening_keys: &Vec<OpeningKey>| {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);

            opening_keys.iter().map(| opening|  {

                let public_key = secp.commit_sum(
                        vec![
                            string_to_commit(&commits[opening.index])
                        ],
                        vec![mul_commit_secret(&secp, &F, &string_to_secret_key(&secp, &opening.r))],
                    )
                    .unwrap().to_pubkey(&secp).unwrap();

                    hex::encode(public_key.serialize_vec(&secp, false))
            }).collect()
        };

        match self {
            GateProof::MulGate(proof) => {
                match &proof.opening_keys {
                    Some(opening_keys) => {
                        opening(&proof.commits, opening_keys)
                    }, 
                    None => vec![]
                }
            },
            GateProof::AddGate(proof) => {
                match &proof.opening_keys {
                    Some(opening_keys) => {
                        opening(&proof.commits, opening_keys)
                    }, 
                    None => vec![]
                }
            },
        }
    }


}


#[derive(Debug,Serialize, Deserialize, Clone)]
pub struct Proof {
    pub proof: Vec<GateProof>,
    pub inputs: Vec<String>,
}

pub struct Pedersen(Secp256k1);

pub fn to_secret_key<T: Field>(secp: &Secp256k1, value: &T) -> SecretKey {

    if value.eq(&T::from(0)) {
        return key::ZERO_KEY
    } 

    let value = wrapp_value(value);
 
    let b = value.to_biguint();

    let bytes = b.to_bytes_be();
    let mut v = vec![0u8; 32 - bytes.len()];
    v.extend_from_slice(&bytes);
    SecretKey::from_slice(secp, &v).expect(&format!("expect value {}", value))

}

pub fn string_to_commit(value: &String) -> Commitment {

    let data = hex::decode(value).unwrap();
    Commitment::from_vec(data)
}

pub fn string_to_secret_key(secp: &Secp256k1, value: &String) -> SecretKey {

    let data = hex::decode(value).unwrap();
    SecretKey::from_slice(secp, &data).expect(&format!("expect value {}", value))
}

fn computes_opening_value(
    secp: &Secp256k1,
    value: &SecretKey,
    x: &SecretKey,
    t: &SecretKey,
) -> SecretKey {
    let mut value = value.clone();

    value.mul_assign(&secp, &x).unwrap();

    secp.blind_sum(vec![value, t.clone()], vec![]).unwrap()
}

fn mul_commit_secret(secp: &Secp256k1, w: &Commitment, r: &SecretKey) -> Commitment {
    let mut public_key = w.to_pubkey(secp).unwrap();

    public_key.mul_assign(secp, r).unwrap();

    Commitment::from_pubkey(secp, &public_key).unwrap()
}


fn wrapp_value<T: Field>(v: &T)-> T {
    let N = T::try_from_str_no_mod("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
    let P = T::try_from_str_no_mod("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();
    let value = v.clone();
    let value = if value.ge(&N) {
        value - P + N
    } else if value.lt(&T::from(0)) {
        value + N
    }
    else {
        value
    };

    value
}
fn value_to_commit<T: Field>(secp: &Secp256k1, v: &T, blind: SecretKey) -> Commitment {

    let value = wrapp_value(v);

    secp.commit_blind(blind, to_secret_key(secp, &value)).unwrap()
}

fn secret_value_to_commit(secp: &Secp256k1, value: SecretKey, blind: SecretKey) -> Commitment {
    secp.commit_blind(blind, value).unwrap()
}


pub static POW_2_128: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0]);

// Since the private key is split into two parts and used as input, we can only calculate the public key 
// corresponding to the partial private key from the witness, and then use these two public keys to calculate
// the public key of the original private key
// pubkey0 = Commit0 - keyopen0 * F
// pubkey1 = Commit1 - keyopen1 * F 
// original_pubkey = pubkey0 * 2^128 + pubkey1
fn open_public_key(
    secp: &Secp256k1,
    public_keys: &Vec<String>
) -> String {


    let data = hex::decode(public_keys[0].clone()).unwrap();
    let mut public_key_0 = PublicKey::from_slice(secp, &data).unwrap();

    let data = hex::decode(public_keys[1].clone()).unwrap();
    let public_key_1 = PublicKey::from_slice(secp, &data).unwrap();
    
    public_key_0.mul_assign(&secp, &POW_2_128).unwrap();
    let mut v: Vec<&PublicKey> = vec![];
    v.push(&public_key_0);
    v.push(&public_key_1);
    
    let opened_publickey = PublicKey::from_combination(secp, v).unwrap();
   
    hex::encode(opened_publickey.serialize_vec(secp, false))
}


impl Pedersen {
    pub fn new() -> Self {
        Pedersen(Secp256k1::with_caps(ContextFlag::Commit))
    }

    pub fn generate_add_prover<T: Field>(&self, value_l: T, value_r: T, value_o: T, opening_key_indexs: Option<Vec<usize>>) -> Prover<T> {
        let r_l = SecretKey::new(&self.0, &mut thread_rng());
        let r_r = SecretKey::new(&self.0, &mut thread_rng());
        let r_o = SecretKey::new(&self.0, &mut thread_rng());

        let r_b = SecretKey::new(&self.0, &mut thread_rng());
        let commit_add = CommitAdd {
            r_b: r_b.clone(),
            b_commit: value_to_commit(&self.0, &T::from(0), r_b.clone()),
        };

        let witness = PedersenWitness {
            W_L: value_to_commit(&self.0, &value_l, r_l.clone()),
            W_R: value_to_commit(&self.0, &value_r, r_r.clone()),
            W_O: value_to_commit(&self.0, &value_o, r_o.clone()),
        };

        Prover {
            r_l: r_l.clone(),
            r_r: r_r.clone(),
            r_o: r_o.clone(),
            value_l: value_l,
            value_r: value_r,
            value_o: value_o,
            witness: witness,
            commit_add: Some(commit_add),
            commit_mul: None,
            opening_key_indices: opening_key_indexs
        }
    }

    pub fn generate_mul_prover<T: Field>(&self, value_l: T, value_r: T, value_o: T, opening_key_indexs: Option<Vec<usize>>) -> Prover<T> {
        let r_l = SecretKey::new(&self.0, &mut thread_rng());
        let r_r = SecretKey::new(&self.0, &mut thread_rng());
        let r_o = SecretKey::new(&self.0, &mut thread_rng());

        let t1 = SecretKey::new(&self.0, &mut thread_rng());
        let t2 = SecretKey::new(&self.0, &mut thread_rng());
        let t3 = SecretKey::new(&self.0, &mut thread_rng());
        let t4 = SecretKey::new(&self.0, &mut thread_rng());
        let t5 = SecretKey::new(&self.0, &mut thread_rng());

        let witness = PedersenWitness {
            W_L: value_to_commit(&self.0, &value_l, r_l.clone()),
            W_R: value_to_commit(&self.0, &value_r, r_r.clone()),
            W_O: value_to_commit(&self.0, &value_o, r_o.clone()),
        };

        let c3_commit = self
            .0
            .commit_sum(
                vec![
                    mul_commit_secret(&self.0, &witness.W_R, &t1),
                    mul_commit_secret(&self.0, &F, &t4),
                ],
                vec![],
            )
            .unwrap();

        let commit_mul = CommitMul {
            t1: t1.clone(),
            t2: t2.clone(),
            t3: t3.clone(),
            t4: t4.clone(),
            t5: t5.clone(),
            c1_commit: secret_value_to_commit(&self.0, t1.clone(), t3.clone()), //𝐶1 = 𝐶𝑜𝑚(𝑡1,𝑡3),
            c2_commit: secret_value_to_commit(&self.0, t2.clone(), t5.clone()), //𝐶2 = 𝐶𝑜𝑚(𝑡2,𝑡5)
            c3_commit: c3_commit,                                    //𝐶3 = 𝑡1×𝑊𝑅+𝑡4×𝐹
        };

        Prover {
            r_l: r_l.clone(),
            r_r: r_r.clone(),
            r_o: r_o.clone(),
            value_l: value_l,
            value_r: value_r,
            value_o: value_o,
            witness: witness,
            commit_add: None,
            commit_mul: Some(commit_mul),
            opening_key_indices: opening_key_indexs
        }
    }

    //The prover then computes the opening value: 𝑧=𝑥(𝑟𝐿+𝑟𝑅−𝑟𝑂)+𝑟𝐵 and sends it to the verifier.
    pub fn prove_add_gate<T: Field>(&self, x: T, prover: &Prover<T>) -> SecretKey {
        let mut z = self
            .0
            .blind_sum(
                vec![prover.r_l.clone(), prover.r_r.clone()],
                vec![prover.r_o.clone()],
            )
            .unwrap();

        let x = to_secret_key(&self.0, &x);

        z.mul_assign(&self.0, &x).unwrap();

        let r_b = match prover.commit_add.clone() {
            Some(c) => c.r_b,
            None => panic!("No r_b"),
        };

        let z = self.0.blind_sum(vec![z, r_b], vec![]).unwrap();

        z
    }

    pub fn prove_mul_gate<T: Field>(
        &self,
        x: T, //challenge
        prover: &Prover<T>,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey) {
        let x = to_secret_key(&self.0, &x);

        let commit_mul = match &prover.commit_mul {
            Some(c) => c,
            None => panic!("No commit_mul"),
        };

        //𝑒1=𝑤𝐿𝑥+𝑡1
        let e1 = computes_opening_value(&self.0, &to_secret_key(&self.0, &prover.value_l), &x, &commit_mul.t1);
        //𝑒2=𝑤𝑅𝑥+𝑡2
        let e2 = computes_opening_value(&self.0, &to_secret_key(&self.0, &prover.value_r), &x, &commit_mul.t2);
        //𝑧1=𝑟𝐿𝑥+𝑡3
        let z1 = computes_opening_value(&self.0, &prover.r_l, &x, &commit_mul.t3);
        //𝑧2=𝑟𝑅𝑥+𝑡5
        let z2 = computes_opening_value(&self.0, &prover.r_r, &x, &commit_mul.t5);
        //𝑧3=(𝑟𝑂−𝑤𝐿𝑟𝑅)𝑥+𝑡4
        let mut w_l_r_l = to_secret_key(&self.0, &prover.value_l);
        w_l_r_l.mul_assign(&self.0, &prover.r_r.clone()).unwrap();

        let r_o_w_lr_r = self
            .0
            .blind_sum(vec![prover.r_o.clone()], vec![w_l_r_l])
            .unwrap();

        let z3 = computes_opening_value(&self.0, &r_o_w_lr_r, &x, &commit_mul.t4);
        (e1, e2, z1, z2, z3)
    }

    pub fn verify_add<T: Field>(
        &self,
        x: T,
        witness: &PedersenWitness,
        b_commit: Commitment,
        z: SecretKey,
    ) -> bool {
        let w_sum_tmp = self
            .0
            .commit_sum(
                vec![witness.W_L.clone(), witness.W_R.clone()],
                vec![witness.W_O.clone()],
            )
            .unwrap();

        let x = to_secret_key(&self.0, &x);

        let w_sum = mul_commit_secret(&self.0, &w_sum_tmp, &x);

        let w_right = self.0.commit_sum(vec![w_sum, b_commit], vec![]).unwrap();

        let w_left = value_to_commit(&self.0, &T::from(0), z);

        w_left == w_right
    }

    pub fn verify_mul<T: Field>(
        &self,
        x: T,
        witness: &PedersenWitness,
        commits: &CommitMul,
        (e1, e2, z1, z2, z3): (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey), /*(e1, e2, z1, z2, z3) */
    ) -> bool {
        let x = to_secret_key(&self.0, &x);

        let right_expr = |w: Commitment, c: Commitment| {
            self.0
                .commit_sum(vec![mul_commit_secret(&self.0, &w, &x), c], vec![])
                .unwrap()
        };

        let verify_equation = |e: SecretKey, z: SecretKey, w: Commitment, c: Commitment| {
            let w_left = self.0.commit_blind(z, e).unwrap();
            let w_right = right_expr(w, c);
            w_left == w_right
        };

        //𝐶𝑜𝑚(𝑒1,𝑧1)=𝑥×𝑊𝐿+𝐶1
        let equation_1 =  verify_equation(e1.clone(), z1, witness.W_L, commits.c1_commit);

        // 𝐶𝑜𝑚(𝑒2,𝑧2)=𝑥×𝑊𝑅+𝐶2
        let equation_2 = verify_equation(e2.clone(), z2, witness.W_R, commits.c2_commit);

        //𝑒1×𝑊𝑅+𝑧3×𝐹=𝑥×𝑊𝑂+𝐶3
        // 𝐶3 = 𝑡1×𝑊𝑅+𝑡4×𝐹

        let w_left = self
            .0
            .commit_sum(
                vec![
                    mul_commit_secret(&self.0, &witness.W_R, &e1),
                    mul_commit_secret(&self.0, &F, &z3),
                ],
                vec![],
            )
            .unwrap();

        let w_right = right_expr(witness.W_O, commits.c3_commit);

        let equation_3 = w_left == w_right;

        equation_1 && equation_2 && equation_3
    }


    pub fn verify_prover<T: Field>(
        &self,
        prover: &Prover<T>,
    ) -> bool {

        let is_add_gate = match &prover.commit_add {
            Some(_) => true,
            None => false,
        };

        let x = random_32_bytes::<T>();
        
        if is_add_gate {

            let b_commit = match prover.commit_add.clone() {
                Some(c) => c.b_commit,
                None => panic!("No b_commit"),
            };


            let z = self.prove_add_gate(x.clone(), &prover);

            let success = self.verify_add(x.clone(), &prover.witness, b_commit, z);

            if !success {
                    
                println!("add gate fail prover: {:?}", prover);
            }
            success

        } else {

            let tuple = self.prove_mul_gate(x.clone(), &prover);

            let commits_mul = match &prover.commit_mul {
                Some(c) => c,
                None => panic!("No commit_mul"),
            };

            let success = self.verify_mul(x, &prover.witness, &commits_mul, tuple);

            if !success {

                println!("mul gate fail prover: {:?}", prover);
            }

            success
        }

    }


    pub fn generate_proof<T: Field>(
        &self,
        prover: &Prover<T>,
    ) -> GateProof {


        let is_add_gate = match &prover.commit_add {
            Some(_) => true,
            None => false,
        };

        let opening_keys = match &prover.opening_key_indices {
            Some(indexs) => indexs.iter().map(|index| {
                match index {
                    0 => OpeningKey { r: hex::encode(prover.r_l.0), index: 0 },
                    1 => OpeningKey { r: hex::encode(prover.r_r.0), index: 1 },
                    _ => panic!("opening_indexs should never be {}", index)
                }

            }).collect(),
            None => vec![],
        };

        let sha256 = Sha256::new();
        

        if is_add_gate {

            let b_commit = match prover.commit_add.clone() {
                Some(c) => c.b_commit,
                None => panic!("No b_commit"),
            };

            let result  = sha256.chain(prover.witness.W_L.0)
            .chain(prover.witness.W_R.0)
            .chain(prover.witness.W_O.0)
            .chain(b_commit.0).finalize();

     
            let z = self.prove_add_gate(T::from_byte_vector(result.to_vec()), &prover);

            GateProof::AddGate(AddGateProof {
                z: hex::encode(z.0),
                b_commit:hex::encode(b_commit.0) ,
                commits: vec![hex::encode(prover.witness.W_L.0) , hex::encode(prover.witness.W_R.0),hex::encode(prover.witness.W_O.0) ],
                opening_keys: if opening_keys.len() == 0 {None} else {Some(opening_keys)},
            })

        } else {

            let commits_mul = match &prover.commit_mul {
                Some(c) => c,
                None => panic!("No commit_mul"),
            };

            let result  = sha256.chain(prover.witness.W_L.0)
            .chain(prover.witness.W_R.0)
            .chain(prover.witness.W_O.0)
            .chain(commits_mul.c1_commit.0)
            .chain(commits_mul.c2_commit.0)
            .chain(commits_mul.c3_commit.0).finalize();
            

            let tuple = self.prove_mul_gate(T::from_byte_vector(result.to_vec()), &prover);

            GateProof::MulGate(MulGateProof {
                tuple: (hex::encode(tuple.0.0),hex::encode(tuple.1.0),hex::encode(tuple.2.0),hex::encode(tuple.3.0),hex::encode(tuple.4.0) ),
                c_commits: vec![hex::encode(commits_mul.c1_commit.0) , hex::encode(commits_mul.c2_commit.0), hex::encode(commits_mul.c3_commit.0)],
                commits: vec![hex::encode(prover.witness.W_L.0) , hex::encode(prover.witness.W_R.0),hex::encode(prover.witness.W_O.0) ],
                opening_keys: if opening_keys.len() == 0 {None} else {Some(opening_keys)},
            })
        }
    }


    pub fn verify_add_proof<T: Field>(
        &self,
        proof: &AddGateProof,
    ) -> bool {
        let sha256 = Sha256::new();

        let b_commit = string_to_commit(&proof.b_commit);

        let w_l_commit = string_to_commit(&proof.commits[0]);

        let w_r_commit = string_to_commit(&proof.commits[1]);

        let w_o_commit = string_to_commit(&proof.commits[2]);
        

        let result  = sha256.chain(w_l_commit.0)
        .chain(w_r_commit.0)
        .chain(w_o_commit.0)
        .chain(b_commit.0).finalize();


        let z = string_to_secret_key(&self.0, &proof.z);

        let x = T::from_byte_vector(result.to_vec());

        self.verify_add(x, &PedersenWitness {
            W_L: w_l_commit,
            W_R: w_r_commit,
            W_O: w_o_commit
        },b_commit, z)
    }



    pub fn verify_mul_proof<T: Field>(
        &self,
        proof: &MulGateProof,
    ) -> bool {
        let sha256 = Sha256::new();

        let c1_commit = string_to_commit(&proof.c_commits[0]);
        let c2_commit = string_to_commit(&proof.c_commits[1]);
        let c3_commit = string_to_commit(&proof.c_commits[2]);

        let w_l_commit = string_to_commit(&proof.commits[0]);
        let w_r_commit = string_to_commit(&proof.commits[1]);
        let w_o_commit = string_to_commit(&proof.commits[2]);
        

        let result  = sha256.chain(w_l_commit.0)
        .chain(w_r_commit.0)
        .chain(w_o_commit.0)
        .chain(c1_commit.0)
        .chain(c2_commit.0)
        .chain(c3_commit.0).finalize();

        let x = T::from_byte_vector(result.to_vec());

        let tuple = ( string_to_secret_key(&self.0, &proof.tuple.0),
            string_to_secret_key(&self.0, &proof.tuple.1),
            string_to_secret_key(&self.0, &proof.tuple.2),
            string_to_secret_key(&self.0, &proof.tuple.3),
            string_to_secret_key(&self.0, &proof.tuple.4));



            self.verify_mul(x, &PedersenWitness {
                W_L: w_l_commit,
                W_R: w_r_commit,
                W_O: w_o_commit
            },&CommitMul {
                t1:SecretKey::new(&self.0, &mut thread_rng()),
                t2:SecretKey::new(&self.0, &mut thread_rng()),
                t3:SecretKey::new(&self.0, &mut thread_rng()),
                t4:SecretKey::new(&self.0, &mut thread_rng()),
                t5:SecretKey::new(&self.0, &mut thread_rng()),
                c1_commit: c1_commit,
                c2_commit: c2_commit,
                c3_commit: c3_commit
            }, tuple)
    }




    pub fn verify_proof<T: Field>(
        &self,
        proof: &GateProof,
    ) -> bool {
        match proof {
            GateProof::AddGate(p) => {
                self.verify_add_proof::<T>(&p)
            }
            GateProof::MulGate(p) => {
                self.verify_mul_proof::<T>(&p)
            }
        }
    }


    pub fn verify_public_key(
        &self,
        pubkey_expected: &str,
        public_keys: &Vec<String>
    ) -> bool {

        let pubkey = open_public_key(&self.0, public_keys);
        
        pubkey.eq(&String::from(pubkey_expected))

    }

}


#[cfg(test)]
mod test {
    use rand_0_5::RngCore;
    use zokrates_field::{Secp256k1Field, Field, Bn128Field};
    use super::*;
    


    fn test_verify_add_prover<T: Field>(a: T, b: T, c: T) {

        let pederson = Pedersen::new();
        // 4 = 1 + 3
        let prover = pederson.generate_add_prover(a.clone(), b.clone(), c.clone(), None);

    
        let b_commit = match prover.commit_add.clone() {
            Some(c) => c.b_commit,
            None => panic!("No b_commit"),
        };
    

        let mut rng =  thread_rng();

        // x is challenge
        let x = T::from(rng.next_u32());
        let z = pederson.prove_add_gate::<T>(x.clone(), &prover);
    
    
        let success = pederson.verify_add(x.clone(), &prover.witness, b_commit, z);
    


        assert!(success, "test_verify_add_prover failed:  {:?} + {:?} = {:?},  prover: {:?}", a, b, c, prover);

    }

    fn test_verify_mul_prover<T: Field>(a: T, b: T, c: T) {

        let pederson = Pedersen::new();

        let mut rng =  thread_rng();
        let x = T::from(rng.next_u32());

    
        let prover = pederson.generate_mul_prover(a, b, c, None);

    
        let tuple = pederson.prove_mul_gate::<T>(x.clone(), &prover);

        let commits_mul = match &prover.commit_mul {
            Some(c) => c,
            None => panic!("No commit_mul"),
        };

        let success = pederson.verify_mul(x, &prover.witness, &commits_mul, tuple);

        assert!(success, "test_verify_mul_prover failed {:?}", prover);
    }


    #[test]
    fn test_all_api() {


        test_verify_add_prover(Secp256k1Field::from_i64_no_mod(1), Secp256k1Field::from_i64_no_mod(1), Secp256k1Field::from_i64_no_mod(2));
        test_verify_add_prover(Secp256k1Field::from_i64_no_mod(0), Secp256k1Field::from_i64_no_mod(1), Secp256k1Field::from_i64_no_mod(1));
        test_verify_add_prover(Secp256k1Field::from_i64_no_mod(0), Secp256k1Field::from_i64_no_mod(1), Secp256k1Field::from_i64_no_mod(1));
        test_verify_add_prover(Secp256k1Field::from_i64_no_mod(-1), Secp256k1Field::from_i64_no_mod(-1), Secp256k1Field::from_i64_no_mod(-2));
        test_verify_add_prover(Secp256k1Field::from_i64_no_mod(1), Secp256k1Field::from_i64_no_mod(-1), Secp256k1Field::from_i64_no_mod(0));
        test_verify_add_prover(Secp256k1Field::from_i64_no_mod(1), 
            Secp256k1Field::from(Secp256k1Field::try_from_str_no_mod("115792089237316195423570985008687907853269984665640564039457584007908834671662", 10).unwrap()), 
            Secp256k1Field::from_i64_no_mod(0));
        
            test_verify_add_prover(Secp256k1Field::from(2), 
            Secp256k1Field::from(Secp256k1Field::try_from_str_no_mod("115792089237316195423570985008687907853269984665640564039457584007908834671661", 10).unwrap()), 
            Secp256k1Field::from(0));

        

       test_verify_mul_prover(Secp256k1Field::from_i64_no_mod(1), Secp256k1Field::from_i64_no_mod(1), Secp256k1Field::from_i64_no_mod(1));
       test_verify_mul_prover(Secp256k1Field::from_i64_no_mod(100), Secp256k1Field::from_i64_no_mod(100), Secp256k1Field::from_i64_no_mod(10000));
       test_verify_mul_prover(Secp256k1Field::from_i64_no_mod(1), 
       Secp256k1Field::try_from_str_no_mod("115792089237316195423570985008687907853269984665640564039457584007908834671662", 10).unwrap(), 
       Secp256k1Field::from_i64_no_mod(-1));

       test_verify_mul_prover(Secp256k1Field::from_i64_no_mod(-1), 
       Secp256k1Field::from_i64_no_mod(-1), 
       Secp256k1Field::from_i64_no_mod(1));

    }


    fn test_add_proof<T: Field>(a: T, b: T, c: T) {

        let pederson = Pedersen::new();
        let prover = pederson.generate_add_prover(a.clone(), b.clone(), c.clone(), None);
        let proof = pederson.generate_proof::<T>(&prover);
        let success = pederson.verify_proof::<T>(&proof);
        assert!(success, "test_add_proof fail a: {}, b: {}, c: {}", a, b, c);
    }

    fn test_mul_proof<T: Field>(a: T, b: T, c: T) {

        let pederson = Pedersen::new();
        let prover = pederson.generate_mul_prover(a.clone(), b.clone(), c.clone(), None);
        let proof = pederson.generate_proof::<T>(&prover);
        let success = pederson.verify_proof::<T>(&proof);
        assert!(success, "test_mul_proof fail a: {}, b: {}, c: {}", a, b, c);
    }

    #[test]
    fn test_generate_proof() {

        test_add_proof(Bn128Field::from(1), Bn128Field::from(1), Bn128Field::from(2));
        test_add_proof(Bn128Field::from(11), Bn128Field::from(1), Bn128Field::from(12));
        
        test_add_proof(Bn128Field::from(1000000), Bn128Field::from(100), Bn128Field::from(1000100));


        test_mul_proof(Bn128Field::from(1), Bn128Field::from(1), Bn128Field::from(1));

        test_mul_proof(Bn128Field::from(2), Bn128Field::from(2), Bn128Field::from(4));


        test_add_proof(Secp256k1Field::from(1), Secp256k1Field::from(1), Secp256k1Field::from(2));
        test_add_proof(Secp256k1Field::from(11), Secp256k1Field::from(1), Secp256k1Field::from(12));
        
        test_add_proof(Secp256k1Field::from(1000000), Secp256k1Field::from(100), Secp256k1Field::from(1000100));


        test_mul_proof(Secp256k1Field::from(1), Secp256k1Field::from(1), Secp256k1Field::from(1));

        test_mul_proof(Secp256k1Field::from(2), Secp256k1Field::from(2), Secp256k1Field::from(4));
    }


    
    #[test]
    fn test_to_secret_key() {

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let x = Secp256k1Field::try_from_dec_str("115792089237316195423570985008687907853269984665640564039457584007908834671663").unwrap();

        let x = to_secret_key(&secp, &x);

        assert_eq!(x, to_secret_key(&secp, &Secp256k1Field::from(0)));

        let x = Secp256k1Field::try_from_dec_str("115792089237316195423570985008687907853269984665640564039457584007908834671664").unwrap();

        let x = to_secret_key(&secp, &x);

        assert_eq!(x, to_secret_key(&secp, &Secp256k1Field::from(1)));

        let x = Secp256k1Field::try_from_dec_str("1").unwrap();

        let x = to_secret_key(&secp, &x);

        assert_eq!(x, to_secret_key(&secp, &Secp256k1Field::from(1)));

        let x = Secp256k1Field::try_from_dec_str("115792089237316195423570985008687907853269984665640564039457584007908834671662").unwrap();

        let x = to_secret_key(&secp, &x);

        assert_eq!(x, to_secret_key(&secp, &Secp256k1Field::try_from_dec_str("115792089237316195423570985008687907853269984665640564039457584007908834671662").unwrap()));
        

        //Com(x, r) == Com(x-N, r)
        let r = Secp256k1Field::try_from_dec_str("3").unwrap();
        let x = Secp256k1Field::from(-1);
        let N = Secp256k1Field::try_from_str("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();

        
        let c1 = secp.commit_blind( to_secret_key(&secp, &x), to_secret_key(&secp, &r)).unwrap();
        println!("c1 {:?}", c1);


        let c3 = secp.commit_blind( to_secret_key(&secp, &(x + N)),  to_secret_key(&secp, &r)).unwrap();
        
        assert_eq!(c1, c3);

    }  


    #[test]
    fn test_open_origin_public_key() {

        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        let mut public_keys: Vec<String> = vec![];

        public_keys.push(String::from("0490bccc7e8d1a49a38c497cfcc068cb014d9396e4ac8b6c0e58419ec0486144d7bc5e2b996f368cd67ac103fd2acf28117d13b2ec2525e12b4b4fc49fccd3aec5"));
        public_keys.push(String::from("04551e82ce27bcb8d71cb0fa39b4caf3065c8c18179a0c8f548eacf5df52a2ebf7802b3de33ae8f0e94ec8e98ab0a17f5a9a300634f25e0af2bb11b6ef6225d343"));

        
        let opened_publickey = open_public_key(&secp, &public_keys);

        assert_eq!(opened_publickey, String::from("0494d6deea102c33307a5ae7e41515198f6fc19d3b11abeca5bff56f1011ed2d8e3d8f02cbd20e8c53d8050d681397775d0dc8b0ad406b261f9b4c94404201cab3"));

    }  




    #[test]
    fn test_open_public_key_of_partial_secret_key() {

        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        let value = Secp256k1Field::try_from_str_no_mod("00000000000000000000000000000000ec4916dd28fc4c10d78e287ca5d9cc51", 16).unwrap();
        let blind = string_to_secret_key(&secp,&String::from("0750b10b3b1124eb62484eddd27ace074168e310d3edae11f29129bb1d666241"));
        

        let commit = value_to_commit(&secp, &value, blind.clone());


        let rf = mul_commit_secret(&secp, &F, &blind);

        let public_key = secp.commit_sum(
            vec![
                commit
            ],
            vec![rf],
        )
        .unwrap().to_pubkey(&secp).unwrap();
        
        let public_key_str =  hex::encode(public_key.serialize_vec(&secp, false));

        assert_eq!(public_key_str, "0490bccc7e8d1a49a38c497cfcc068cb014d9396e4ac8b6c0e58419ec0486144d7bc5e2b996f368cd67ac103fd2acf28117d13b2ec2525e12b4b4fc49fccd3aec5")
    }  


    #[test]
    fn test_open_public_key() {
        let mut public_keys_vec: Vec<String> = vec![];
        let pederson = Pedersen::new();
        let a = Secp256k1Field::try_from_str_no_mod("00000000000000000000000000000000ec4916dd28fc4c10d78e287ca5d9cc51", 16).unwrap();
        let b = Secp256k1Field::try_from_str_no_mod("01", 16).unwrap();
        let c = Secp256k1Field::try_from_str_no_mod("00000000000000000000000000000000ec4916dd28fc4c10d78e287ca5d9cc51", 16).unwrap();
        let prover = pederson.generate_mul_prover(a.clone(), b.clone(), c.clone(), 
        Some(vec![0]));
        
        let proof = pederson.generate_proof::<Secp256k1Field>(&prover);
        let opening_public_keys = proof.opening_public_keys();
        println!("opening_public_keys {:?}", opening_public_keys);
        public_keys_vec.extend(opening_public_keys.iter().cloned());

        let a = Secp256k1Field::try_from_str_no_mod("00000000000000000000000000000000ee1ae73cbfde08c6b37324cbfaac8bc5", 16).unwrap();
        let b = Secp256k1Field::try_from_str_no_mod("01", 16).unwrap();
        let c = Secp256k1Field::try_from_str_no_mod("00000000000000000000000000000000ee1ae73cbfde08c6b37324cbfaac8bc5", 16).unwrap();
        let prover = pederson.generate_mul_prover(a.clone(), b.clone(), c.clone(), 
        Some(vec![0]));
        
        let proof = pederson.generate_proof::<Secp256k1Field>(&prover);
        let opening_public_keys = proof.opening_public_keys();
        println!("opening_public_keys {:?}", opening_public_keys);
        public_keys_vec.extend(opening_public_keys.iter().cloned());


        let success = pederson.verify_public_key(
            "0494d6deea102c33307a5ae7e41515198f6fc19d3b11abeca5bff56f1011ed2d8e3d8f02cbd20e8c53d8050d681397775d0dc8b0ad406b261f9b4c94404201cab3", 
            &public_keys_vec);
        assert!(success);
        
    }  
}
