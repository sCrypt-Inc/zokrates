use secp256k1zkp::{
    constants, key, pedersen::Commitment, ContextFlag, PublicKey, Secp256k1, SecretKey,
};
use serde::{Deserialize, Serialize};
use zokrates_field::Field;
use zokrates_field::Bn128Field;
use zokrates_field::Secp256k1Field;
use rand_0_5::{thread_rng, Rng};

use sha2::{Sha256, Sha512, Digest};


fn random_32_bytes<T: Field>() -> T {
    let mut rng = thread_rng();
    let mut ret = [0u8; 32];
    rng.fill(&mut ret);
    T::from_byte_vector(ret.to_vec())
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
pub struct Prover {
    r_l: SecretKey,
    r_r: SecretKey,
    r_o: SecretKey,
    value_l: SecretKey,
    value_r: SecretKey,
    value_o: SecretKey,
    witness: PedersenWitness,
    commit_add: Option<CommitAdd>,
    commit_mul: Option<CommitMul>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AddGateProof {
    z: String,
    b_commit: String,
    commits: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MulGateProof {
    tuple:  (String, String, String, String, String),
    c_commits: Vec<String>,
    commits:Vec<String>,
}

#[derive(Debug,Serialize, Deserialize, Clone)]
pub enum Proof {
    AddGate(AddGateProof),
    MulGate(MulGateProof),
}



pub struct Pedersen(Secp256k1);

pub fn to_secret_key<T: Field>(secp: &Secp256k1, value: &T) -> SecretKey {

    let N = T::from_byte_vector(vec![65, 65, 54, 208, 140, 94, 210, 191, 59, 160, 72, 175, 230, 220, 174, 186, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]);

    if value.eq(&T::from(0)) {
        return key::ZERO_KEY
    } 

    if value.eq(&N) {
        return key::ZERO_KEY
    } 
    
    let b = if value.gt(&N) {
        value.to_biguint() % N.to_biguint()

    } else {
        value.to_biguint()
    };

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

impl Pedersen {
    pub fn new() -> Self {
        Pedersen(Secp256k1::with_caps(ContextFlag::Commit))
    }

    pub fn generate_add_prover<T: Field>(&self, value_l: T, value_r: T, value_o: T) -> Prover {
        let r_l = SecretKey::new(&self.0, &mut thread_rng());
        let r_r = SecretKey::new(&self.0, &mut thread_rng());
        let r_o = SecretKey::new(&self.0, &mut thread_rng());

        let r_b = SecretKey::new(&self.0, &mut thread_rng());
        let commit_add = CommitAdd {
            r_b: r_b.clone(),
            b_commit: self.0.commit(0, r_b.clone()).unwrap(),
        };

        Prover {
            r_l: r_l.clone(),
            r_r: r_r.clone(),
            r_o: r_o.clone(),
            value_l: to_secret_key(&self.0, &value_l),
            value_r: to_secret_key(&self.0, &value_r),
            value_o: to_secret_key(&self.0, &value_o),
            witness: PedersenWitness {
                W_L: self.0.commit_blind(to_secret_key(&self.0, &value_l), r_l.clone()).unwrap(),
                W_R: self.0.commit_blind(to_secret_key(&self.0, &value_r), r_r.clone()).unwrap(),
                W_O: self.0.commit_blind(to_secret_key(&self.0, &value_o), r_o.clone()).unwrap(),
            },
            commit_add: Some(commit_add),
            commit_mul: None,
        }
    }

    pub fn generate_mul_prover<T: Field>(&self, value_l: T, value_r: T, value_o: T) -> Prover {
        let r_l = SecretKey::new(&self.0, &mut thread_rng());
        let r_r = SecretKey::new(&self.0, &mut thread_rng());
        let r_o = SecretKey::new(&self.0, &mut thread_rng());

        let t1 = SecretKey::new(&self.0, &mut thread_rng());
        let t2 = SecretKey::new(&self.0, &mut thread_rng());
        let t3 = SecretKey::new(&self.0, &mut thread_rng());
        let t4 = SecretKey::new(&self.0, &mut thread_rng());
        let t5 = SecretKey::new(&self.0, &mut thread_rng());

        let p_witness = PedersenWitness {
            W_L: self.0.commit_blind(to_secret_key(&self.0, &value_l), r_l.clone()).unwrap(),
            W_R: self.0.commit_blind(to_secret_key(&self.0, &value_r), r_r.clone()).unwrap(),
            W_O: self.0.commit_blind(to_secret_key(&self.0, &value_o), r_o.clone()).unwrap(),
        };

        let F = self.0.commit(0, key::ONE_KEY).unwrap();

        let c3_commit = self
            .0
            .commit_sum(
                vec![
                    mul_commit_secret(&self.0, &p_witness.W_R, &t1),
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
            c1_commit: self.0.commit_blind(t1, t3.clone()).unwrap(), //𝐶1 = 𝐶𝑜𝑚(𝑡1,𝑡3),
            c2_commit: self.0.commit_blind(t2, t5.clone()).unwrap(), //𝐶2 = 𝐶𝑜𝑚(𝑡2,𝑡5)
            c3_commit: c3_commit,                                    //𝐶3 = 𝑡1×𝑊𝑅+𝑡4×𝐹
        };

        Prover {
            r_l: r_l.clone(),
            r_r: r_r.clone(),
            r_o: r_o.clone(),
            value_l: to_secret_key(&self.0, &value_l),
            value_r: to_secret_key(&self.0, &value_r),
            value_o: to_secret_key(&self.0, &value_o),
            witness: p_witness,
            commit_add: None,
            commit_mul: Some(commit_mul),
        }
    }

    //The prover then computes the opening value: 𝑧=𝑥(𝑟𝐿+𝑟𝑅−𝑟𝑂)+𝑟𝐵 and sends it to the verifier.
    pub fn prove_add_gate<T: Field>(&self, x: T, prover: &Prover) -> SecretKey {
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
        prover: &Prover,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey) {
        let x = to_secret_key(&self.0, &x);

        let commit_mul = match &prover.commit_mul {
            Some(c) => c,
            None => panic!("No commit_mul"),
        };

        //𝑒1=𝑤𝐿𝑥+𝑡1
        let e1 = computes_opening_value(&self.0, &prover.value_l, &x, &commit_mul.t1);
        //𝑒2=𝑤𝑅𝑥+𝑡2
        let e2 = computes_opening_value(&self.0, &prover.value_r, &x, &commit_mul.t2);
        //𝑧1=𝑟𝐿𝑥+𝑡3
        let z1 = computes_opening_value(&self.0, &prover.r_l, &x, &commit_mul.t3);
        //𝑧2=𝑟𝑅𝑥+𝑡5
        let z2 = computes_opening_value(&self.0, &prover.r_r, &x, &commit_mul.t5);
        //𝑧3=(𝑟𝑂−𝑤𝐿𝑟𝑅)𝑥+𝑡4
        let mut 𝑤_l_𝑟_l = prover.value_l.clone();
        𝑤_l_𝑟_l.mul_assign(&self.0, &prover.r_r.clone()).unwrap();

        let r_o_𝑤_l𝑟_r = self
            .0
            .blind_sum(vec![prover.r_o.clone()], vec![𝑤_l_𝑟_l])
            .unwrap();

        let z3 = computes_opening_value(&self.0, &r_o_𝑤_l𝑟_r, &x, &commit_mul.t4);
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

        let w_left = self.0.commit(0, z.clone()).unwrap();

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
            let w_left = self.0.commit_blind(e, z).unwrap();
            let w_right = right_expr(w, c);
            w_left == w_right
        };

        //𝐶𝑜𝑚(𝑒1,𝑧1)=𝑥×𝑊𝐿+𝐶1
        let equation_1 =  verify_equation(e1.clone(), z1, witness.W_L, commits.c1_commit);

        // 𝐶𝑜𝑚(𝑒2,𝑧2)=𝑥×𝑊𝑅+𝐶2
        let equation_2 = verify_equation(e2.clone(), z2, witness.W_R, commits.c2_commit);

        //𝑒1×𝑊𝑅+𝑧3×𝐹=𝑥×𝑊𝑂+𝐶3
        // 𝐶3 = 𝑡1×𝑊𝑅+𝑡4×𝐹

        let F = self.0.commit(0, key::ONE_KEY).unwrap();

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
        prover: &Prover,
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
        prover: &Prover,
    ) -> Proof {


        let is_add_gate = match &prover.commit_add {
            Some(_) => true,
            None => false,
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

            Proof::AddGate(AddGateProof {
                z: hex::encode(z.0),
                b_commit:hex::encode(b_commit.0) ,
                commits: vec![hex::encode(prover.witness.W_L.0) , hex::encode(prover.witness.W_R.0),hex::encode(prover.witness.W_O.0) ]
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

            Proof::MulGate(MulGateProof {
                tuple: (hex::encode(tuple.0.0),hex::encode(tuple.1.0),hex::encode(tuple.2.0),hex::encode(tuple.3.0),hex::encode(tuple.4.0) ),
                c_commits: vec![hex::encode(commits_mul.c1_commit.0) , hex::encode(commits_mul.c2_commit.0), hex::encode(commits_mul.c3_commit.0)],
                commits: vec![hex::encode(prover.witness.W_L.0) , hex::encode(prover.witness.W_R.0),hex::encode(prover.witness.W_O.0) ]
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

        let success = self.verify_add(x, &PedersenWitness {
            W_L: w_l_commit,
            W_R: w_r_commit,
            W_O: w_o_commit
        },b_commit, z);


        success
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



        let success = self.verify_mul(x, &PedersenWitness {
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
        }, tuple);


        success
    }




    pub fn verify_proof<T: Field>(
        &self,
        proof: &Proof,
    ) -> bool {
        match proof {
            Proof::AddGate(p) => {
                self.verify_add_proof::<T>(&p)
            }
            Proof::MulGate(p) => {
                self.verify_mul_proof::<T>(&p)
            }
        }
    }

}


#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn test_all_api() {

        let pederson = Pedersen::new();
        // 4 = 1 + 3
        let prover = pederson.generate_add_prover(Secp256k1Field::from(100), Secp256k1Field::from(10000), Secp256k1Field::from(10100));
        println!("prover: {:?}", prover);
    
        let b_commit = match prover.commit_add.clone() {
            Some(c) => c.b_commit,
            None => panic!("No b_commit"),
        };
    
        println!("b_commit: {:?}", b_commit);
    
        // x is challenge
        let x = Secp256k1Field::from(1);
        let z = pederson.prove_add_gate(x.clone(), &prover);
    
        println!("z: {:?}", z);
    
        let success = pederson.verify_add(x.clone(), &prover.witness, b_commit, z);
    
        assert!(success, "𝐶𝑜𝑚(0,𝑧)=𝑥×(𝑊𝐿+𝑊𝑅−𝑊𝑂)+𝐵 fail");
    
        // 1 = 1 * 1
        let prover = pederson.generate_mul_prover(Secp256k1Field::from(100), Secp256k1Field::from(1), Secp256k1Field::from(100));
        println!("prover: {:?}", prover);
    
        let tuple = pederson.prove_mul_gate(x.clone(), &prover);
    
        println!("tuple: {:?}", tuple);
    
        let commits_mul = match &prover.commit_mul {
            Some(c) => c,
            None => panic!("No commit_mul"),
        };
    
        let success = pederson.verify_mul(x, &prover.witness, &commits_mul, tuple);
    
        assert!(success, " 1 = 1 * 1 fail");
    }


    fn test_add_proof<T: Field>(a: T, b: T, c: T) {

        let pederson = Pedersen::new();
        let prover = pederson.generate_add_prover(a.clone(), b.clone(), c.clone());
        let proof = pederson.generate_proof::<T>(&prover);
        let success = pederson.verify_proof::<T>(&proof);
        assert!(success, "test_add_proof fail a: {}, b: {}, c: {}", a, b, c);
    }

    fn test_mul_proof<T: Field>(a: T, b: T, c: T) {

        let pederson = Pedersen::new();
        let prover = pederson.generate_mul_prover(a.clone(), b.clone(), c.clone());
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

        

        let n =   Secp256k1Field::try_from_str("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142", 16).unwrap();


        let n = to_secret_key(&secp, &n);


        assert_eq!(n, to_secret_key(&secp, &Secp256k1Field::from(1)));


        let n =   Secp256k1Field::try_from_str("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();


        let n = to_secret_key(&secp, &n);


        assert_eq!(n, to_secret_key(&secp, &Secp256k1Field::from(0)));

    }
    
}
