use crate::scheme::{NonUniversalScheme, Scheme};
use crate::solidity::solidity_pairing_lib;
use crate::{G1Affine, G2Affine, MpcScheme, SolidityCompatibleField, SolidityCompatibleScheme, ToScryptString};
/* =============== add by sCrypt */
use crate::scrypt::{scrypt_pairing_lib_bn128};
use crate::{ScryptCompatibleField, ScryptCompatibleScheme};
/* =============== end */
use regex::Regex;
use serde::{Deserialize, Serialize};
use zokrates_field::Field;
use zokrates_common::helpers::{CurveParameter};


#[derive(Serialize)]
pub struct G16;

#[derive(Serialize, Deserialize, Clone)]
pub struct ProofPoints<G1, G2> {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}

#[derive(Serialize, Deserialize)]
pub struct VerificationKey<G1, G2> {
    pub alpha: G1,
    pub beta: G2,
    pub gamma: G2,
    pub delta: G2,
    pub gamma_abc: Vec<G1>,
}

impl<T: Field> Scheme<T> for G16 {
    const NAME: &'static str = "g16";

    type VerificationKey = VerificationKey<G1Affine, G2Affine>;
    type ProofPoints = ProofPoints<G1Affine, G2Affine>;
}

impl<T: Field> NonUniversalScheme<T> for G16 {}
impl<T: Field> MpcScheme<T> for G16 {}

impl<T: SolidityCompatibleField> SolidityCompatibleScheme<T> for G16 {
    type Proof = Self::ProofPoints;

    fn export_solidity_verifier(vk: <G16 as Scheme<T>>::VerificationKey) -> String {
        let (mut template_text, solidity_pairing_lib_sans_bn256g2) =
            (String::from(CONTRACT_TEMPLATE_BN128), solidity_pairing_lib(false));

        let vk_regex = Regex::new(r#"(<%vk_[^i%]*%>)"#).unwrap();
        let vk_gamma_abc_len_regex = Regex::new(r#"(<%vk_gamma_abc_length%>)"#).unwrap();
        let vk_gamma_abc_repeat_regex = Regex::new(r#"(<%vk_gamma_abc_pts%>)"#).unwrap();
        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();
        let input_loop = Regex::new(r#"(<%input_loop%>)"#).unwrap();
        let input_argument = Regex::new(r#"(<%input_argument%>)"#).unwrap();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.alpha.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.beta.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.gamma.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.delta.to_string().as_str())
            .into_owned();

        let gamma_abc_count: usize = vk.gamma_abc.len();
        template_text = vk_gamma_abc_len_regex
            .replace(
                template_text.as_str(),
                format!("{}", gamma_abc_count).as_str(),
            )
            .into_owned();

        template_text = vk_input_len_regex
            .replace(
                template_text.as_str(),
                format!("{}", gamma_abc_count - 1).as_str(),
            )
            .into_owned();

        // feed input values only if there are any
        template_text = if gamma_abc_count > 1 {
            input_loop.replace(
                template_text.as_str(),
                r#"
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }"#,
            )
        } else {
            input_loop.replace(template_text.as_str(), "")
        }
        .to_string();

        // take input values as argument only if there are any
        template_text = if gamma_abc_count > 1 {
            input_argument.replace(
                template_text.as_str(),
                format!(", uint[{}] memory input", gamma_abc_count - 1).as_str(),
            )
        } else {
            input_argument.replace(template_text.as_str(), "")
        }
        .to_string();

        let mut gamma_abc_repeat_text = String::new();
        for (i, g1) in vk.gamma_abc.iter().enumerate() {
            gamma_abc_repeat_text.push_str(
                format!(
                    "vk.gamma_abc[{}] = Pairing.G1Point({});",
                    i,
                    g1.to_string().as_str()
                )
                .as_str(),
            );
            if i < gamma_abc_count - 1 {
                gamma_abc_repeat_text.push_str("\n        ");
            }
        }

        template_text = vk_gamma_abc_repeat_regex
            .replace(template_text.as_str(), gamma_abc_repeat_text.as_str())
            .into_owned();

        let re = Regex::new(r"(?P<v>0[xX][0-9a-fA-F]{64})").unwrap();
        template_text = re.replace_all(&template_text, "uint256($v)").to_string();

        format!("{}{}", solidity_pairing_lib_sans_bn256g2, template_text)
    }
}

const CONTRACT_TEMPLATE_BN128: &str = r#"
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(<%vk_alpha%>);
        vk.beta = Pairing.G2Point(<%vk_beta%>);
        vk.gamma = Pairing.G2Point(<%vk_gamma%>);
        vk.delta = Pairing.G2Point(<%vk_delta%>);
        vk.gamma_abc = new Pairing.G1Point[](<%vk_gamma_abc_length%>);
        <%vk_gamma_abc_pts%>
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof<%input_argument%>
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](<%vk_input_length%>);
        <%input_loop%>
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
"#;


/* =============== add by sCrypt */

impl<T: ScryptCompatibleField> ScryptCompatibleScheme<T> for G16 {
    type Proof = Self::ProofPoints;

    fn export_scrypt_verifier(vk: <G16 as Scheme<T>>::VerificationKey, curve_parameter: CurveParameter) -> String {
        //let (mut verifier_template_text, mut zksnark_template_text, scrypt_pairing_bn256) =
        //(String::from(SCRYPT_CONTRACT_TEMPLATE), String::from(ZKSNARK_TEMPLATE_BN128), scrypt_pairing_lib_bn128());
        let mut zksnark_template_text: String;
        let scrypt_pairing: String;

        let vk_alpha_str: String;
        let vk_beta_str: String;
        let vk_gamma_str: String;
        let vk_delta_str: String;

        if curve_parameter == CurveParameter::Bn128 {
            zksnark_template_text = String::from(ZKSNARK_TEMPLATE_BN128);
            scrypt_pairing = scrypt_pairing_lib_bn128();
            
            vk_alpha_str = vk.alpha.to_scrypt_string();
            vk_beta_str = vk.beta.to_scrypt_string();
            vk_gamma_str = vk.gamma.to_scrypt_string();
            vk_delta_str = vk.delta.to_scrypt_string();
        } else {
            // TODO
            zksnark_template_text = "".to_owned();
            scrypt_pairing = "".to_owned();

            vk_alpha_str = "".to_owned();
            vk_beta_str = "".to_owned();
            vk_gamma_str = "".to_owned();
            vk_delta_str = "".to_owned();
        }

        let vk_regex = Regex::new(r#"(<%vk%>)"#).unwrap();
        let vk_gamma_abc_regex = Regex::new(r#"(<%vk_gamma_abc%>)"#).unwrap();
        let vk_gamma_abc_len_regex = Regex::new(r#"(<%vk_gamma_abc_length%>)"#).unwrap();
        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();
        let input_loop = Regex::new(r#"(<%input_loop%>)"#).unwrap();
        let input_argument = Regex::new(r#"(<%input_argument%>)"#).unwrap();

        let gamma_abc_count: usize = vk.gamma_abc.len();
        
        let mut vk_gamma_abc_text = String::new();

        let mut gamma_abc_repeat_text = String::new();
        gamma_abc_repeat_text.push_str("[");
        for (i, g1) in vk.gamma_abc.iter().enumerate() {
            let to_add = g1.to_scrypt_string();
            gamma_abc_repeat_text.push_str(
                format!(
                    "{}",
                    to_add.as_str()
                )
                .as_str(),
            );
            if i < gamma_abc_count - 1 {
                gamma_abc_repeat_text.push_str(",");
            }
        }
        gamma_abc_repeat_text.push_str("]");
        
        vk_gamma_abc_text.push_str(gamma_abc_repeat_text.as_str());

        zksnark_template_text = vk_gamma_abc_regex
        .replace(zksnark_template_text.as_str(), vk_gamma_abc_text.as_str())
        .into_owned();

        let mut vk_repeat_text = String::new();

        vk_repeat_text.push_str("{\n alpha:");

        vk_repeat_text.push_str(format!(
            "{}",
            vk_alpha_str.as_str()
        )
        .as_str());

        vk_repeat_text.push_str(",\n beta:");

        vk_repeat_text.push_str(format!(
            "{}",
            vk_beta_str.as_str()
        )
        .as_str());
        
        vk_repeat_text.push_str(",\n gamma: ");


        vk_repeat_text.push_str(format!(
            "{}",
            vk_gamma_str.as_str()
        )
        .as_str());

        vk_repeat_text.push_str(",\n delta: ");

        vk_repeat_text.push_str(format!(
            "{}",
            vk_delta_str.as_str()
        )
        .as_str());

        vk_repeat_text.push_str(",\n gammaAbc: gammaAbc\n }");


        zksnark_template_text = vk_regex
        .replace(zksnark_template_text.as_str(), vk_repeat_text.as_str())
        .into_owned();


        zksnark_template_text = if gamma_abc_count > 1 {
            input_argument.replace(
                zksnark_template_text.as_str(),
                r#"int[ZKSNARK.N] inputs, "#,
            )
        } else {
            input_argument.replace(zksnark_template_text.as_str(), "")
        }
        .to_string();



        zksnark_template_text = vk_gamma_abc_len_regex
            .replace_all(
                zksnark_template_text.as_str(),
                format!("{}", gamma_abc_count).as_str(),
            )
            .into_owned();
        
        zksnark_template_text = vk_input_len_regex
            .replace_all(
                zksnark_template_text.as_str(),
                format!("{}", gamma_abc_count - 1).as_str(),
            )
            .into_owned();


        // feed input values only if there are any
        zksnark_template_text = if gamma_abc_count > 1 {
            let repStr = if curve_parameter == CurveParameter::Bn128 {
                r#"
        loop (N) : i {
            G1Point p = BN256.mulG1Point(
                vk.gamma_abc[i + 1],
                inputs[i]
            );
            vk_x = BN256.addG1Points(vk_x, p);
        }"#
            } else {
                r#"
            loop(N_1) : m {
                vk.ic[m][k] = BLS12381.toMont(vk.ic[m][k]);
            }"#
            };

            input_loop.replace(
                &zksnark_template_text.as_str(), repStr,
            )
        } else {
            input_loop.replace(zksnark_template_text.as_str(), "")
        }
        .to_string();


        // feed input values only if there are any
        zksnark_template_text = if gamma_abc_count > 1 {
            input_argument.replace(
                zksnark_template_text.as_str(),
                r#"int[N] inputs, "#,
            )
        } else {
            input_argument.replace(zksnark_template_text.as_str(), "")
        }
        .to_string();


        format!(
            "{}{}",
            scrypt_pairing, zksnark_template_text
        )
    }
}


const ZKSNARK_TEMPLATE_BN128: &str = r#"

const gammaAbc: FixedArray<G1Point, <%vk_gamma_abc_length%>> = <%vk_gamma_abc%>

export const VERIFYING_KEY_DATA = <%vk%>

export type VerifyingKey = {
    millerb1a1: FQ12 // Precalculated miller(alpha, beta)
    gamma: G2Point
    delta: G2Point
    gammaAbc: FixedArray<G1Point, <%vk_gamma_abc_length%>> // Size of array should be N + 1
}

export type Proof = {
    a: G1Point
    b: G2Point
    c: G1Point
}

export const N_PUB_INPUTS = <%vk_input_length%>

export class SNARK extends SmartContractLib {
    @prop()
    static readonly N: bigint = BigInt(N_PUB_INPUTS) // Number of public inputs.

    @method()
    static verify(
        vk: VerifyingKey,
        inputs: FixedArray<bigint, typeof N_PUB_INPUTS>,
        proof: Proof,
    ): boolean {
        let vk_x = vk.gammaAbc[0]
        for (let i = 0; i < N_PUB_INPUTS; i++) {
            const p = BN256.mulG1Point(vk.gammaAbc[i + 1], inputs[i])
            vk_x = BN256.addG1Points(vk_x, p)
        }

        const a0: G1Point = {
            x: proof.a.x,
            y: -proof.a.y,
        }
        return BN256Pairing.pairCheckP4Precalc(
            a0,
            proof.b,
            vk.millerb1a1,
            vk_x,
            vk.gamma,
            proof.c,
            vk.delta
        )
    }
}

"#;
