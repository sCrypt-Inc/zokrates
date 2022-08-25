use crate::scheme::{NonUniversalScheme, Scheme};
use crate::solidity::solidity_pairing_lib;
use crate::{G1Affine, G2Affine, MpcScheme, SolidityCompatibleField, SolidityCompatibleScheme, ToScryptString};
/* =============== add by sCrypt */
use crate::scrypt::{scrypt_pairing_lib};
use crate::{ScryptCompatibleField, ScryptCompatibleScheme};
/* =============== end */
use regex::Regex;
use serde::{Deserialize, Serialize};
use zokrates_field::Field;

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
            (String::from(CONTRACT_TEMPLATE), solidity_pairing_lib(false));

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

const CONTRACT_TEMPLATE: &str = r#"
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

    fn export_scrypt_verifier(vk: <G16 as Scheme<T>>::VerificationKey, alpha_g1_beta_g2: String) -> String {
        

        println!("alpha_g1_beta_g2 {}", alpha_g1_beta_g2);
        let (mut verifier_template_text, mut zksnark_template_text, scrypt_pairing_bn256) =
        (String::from(SCRYPT_CONTRACT_TEMPLATE), String::from(ZKSNARK_TEMPLATE), scrypt_pairing_lib());

        let vk_regex = Regex::new(r#"(<%vk%>)"#).unwrap();
        let vk_millerb1a1_regex = Regex::new(r#"(<%vk_millerb1a1%>)"#).unwrap();  // TODO
        let vk_gamma_abc_len_regex = Regex::new(r#"(<%vk_gamma_abc_length%>)"#).unwrap();
        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();
        let input_loop = Regex::new(r#"(<%input_loop%>)"#).unwrap();
        let input_argument = Regex::new(r#"(<%input_argument%>)"#).unwrap();

        let gamma_abc_count: usize = vk.gamma_abc.len();

        let mut vk_repeat_text = String::new();

        vk_repeat_text.push_str("{");

        vk_repeat_text.push_str(format!(
            "{}",
            vk.alpha.to_scrypt_string().as_str()
        )
        .as_str());

        vk_repeat_text.push_str(",");

        vk_repeat_text.push_str(format!(
            "{}",
            vk.beta.to_scrypt_string().as_str()
        )
        .as_str());

        vk_repeat_text.push_str(",");


        vk_repeat_text.push_str(format!(
            "{}",
            vk.gamma.to_scrypt_string().as_str()
        )
        .as_str());

        vk_repeat_text.push_str(",");

        vk_repeat_text.push_str(format!(
            "{}",
            vk.delta.to_scrypt_string().as_str()
        )
        .as_str());

        vk_repeat_text.push_str(",");

        let mut gamma_abc_repeat_text = String::new();
        gamma_abc_repeat_text.push_str("[");
        for (i, g1) in vk.gamma_abc.iter().enumerate() {
            gamma_abc_repeat_text.push_str(
                format!(
                    "{}",
                    g1.to_scrypt_string().as_str()
                )
                .as_str(),
            );
            if i < gamma_abc_count - 1 {
                gamma_abc_repeat_text.push_str(",");
            }
        }
        gamma_abc_repeat_text.push_str("]");

        vk_repeat_text.push_str(gamma_abc_repeat_text.as_str());

        vk_repeat_text.push_str("}");


        verifier_template_text = vk_regex
        .replace(verifier_template_text.as_str(), vk_repeat_text.as_str())
        .into_owned();


        verifier_template_text = if gamma_abc_count > 1 {
            input_argument.replace(
                verifier_template_text.as_str(),
                r#"int[ZKSNARK.N] inputs, "#,
            )
        } else {
            input_argument.replace(verifier_template_text.as_str(), "")
        }
        .to_string();



        zksnark_template_text = vk_gamma_abc_len_regex
            .replace(
                zksnark_template_text.as_str(),
                format!("{}", gamma_abc_count).as_str(),
            )
            .into_owned();
        
        zksnark_template_text = vk_input_len_regex
            .replace(
                zksnark_template_text.as_str(),
                format!("{}", gamma_abc_count - 1).as_str(),
            )
            .into_owned();

    

        // feed input values only if there are any
        zksnark_template_text = if gamma_abc_count > 1 {
            input_loop.replace(
                zksnark_template_text.as_str(),
                r#"
        loop (N) : i {
            G1Point p = BN256.mulG1Point(
                vk.gamma_abc[i + 1],
                inputs[i]
            );
            vk_x = BN256.addG1Points(vk_x, p);
        }"#,
            )
        } else {
            input_loop.replace(zksnark_template_text.as_str(), "")
        }
        .to_string();


        // feed input values only if there are any
        zksnark_template_text = if gamma_abc_count > 1 {
            input_argument.replace(
                zksnark_template_text.as_str(),
                r#"int[ZKSNARK.N] inputs, "#,
            )
        } else {
            input_argument.replace(zksnark_template_text.as_str(), "")
        }
        .to_string();


        format!(
            "{}{}{}",
            scrypt_pairing_bn256, zksnark_template_text, verifier_template_text
        )
    }
}


const ZKSNARK_TEMPLATE: &str = r#"

struct VerifyingKey {
    G1Point alpha;
    G2Point beta;
    G2Point gamma;
    G2Point delta;
    G1Point[ZKSNARK.N_1] gamma_abc;
}

struct Proof {
    G1Point a;
    G2Point b;
    G1Point c;
}


library ZKSNARK {

    // Number of inputs.
    static const int N = <%vk_input_length%>;
    static const int N_1 = <%vk_gamma_abc_length%>; // N + 1, gamma_abc length


    static function verifyOptimized(<%input_argument%>Proof proof, VerifyingKey vk, FQ12 millerb1a1) : bool {

        G1Point vk_x = vk.gamma_abc[0];

        <%input_loop%>

        return BN256Pairing.pairCheckP4Precalc(
                {proof.a.x, -proof.a.y}, proof.b,
                millerb1a1,
                vk_x, vk.gamma,
                proof.c, vk.delta);
    }

}
"#;



const SCRYPT_CONTRACT_TEMPLATE: &str = r#"
contract Verifier {

    static const VerifyingKey vk = <%vk%>;
    static const FQ12 millerb1a1 = <%vk_millerb1a1%>;

    public function unlock(<%input_argument%>Proof proof) {
        require(ZKSNARK.verifyOptimized(inputs, proof, vk, millerb1a1));
    }
}
"#;

/* =============== end */
