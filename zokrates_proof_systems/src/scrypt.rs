use crate::Scheme;
use serde::{de::DeserializeOwned, Serialize};
use zokrates_field::{Bn128Field, Field};

pub trait ScryptCompatibleField: Field {}
impl ScryptCompatibleField for Bn128Field {}
pub trait ScryptCompatibleScheme<T: ScryptCompatibleField>: Scheme<T> {
    type Proof: From<Self::ProofPoints> + Serialize + DeserializeOwned + Clone;

    fn export_scrypt_verifier(vk: Self::VerificationKey) -> String;
}


pub fn scrypt_pairing_lib() -> String {
    let bn256_lib = r#"
type FQ = int;

struct FQ2 {
    FQ x;
    FQ y;
}

struct FQ6 {
    FQ2 x;
    FQ2 y;
    FQ2 z;
}

struct CurvePoint {
    FQ x;
    FQ y;
    FQ z;
    FQ t;
}

struct TwistPoint {
    FQ2 x;
    FQ2 y;
    FQ2 z;
    FQ2 t;
}

// These two are just to make it easier for users to interface with the code
// by not having them to deal with z and t coords.
struct G1Point {
    FQ x;
    FQ y;
}

struct G2Point {
    FQ2 x;
    FQ2 y;
}

// FQ12 implements the field of size p¹² as a quadratic extension of FQ6
// where ω²=τ.
struct FQ12 {
    FQ6 x;
    FQ6 y;
}

library BN256 {

    // Curve bits:
    static const int CURVE_BITS = 256; 
    static const int CURVE_BITS_P8 = 264; // +8 bits

    // Key int size:
    static const int S = 33;    // 32 bytes plus sign byte
    static const bytes mask = b'000000000000000000000000000000000000000000000000000000000000000001';
    static const bytes zero = b'000000000000000000000000000000000000000000000000000000000000000000';

    // Generator of G1:
    static const CurvePoint G1 = {1, 2, 1, 1};

    // Generator of G2:
    static const TwistPoint G2 = {
        {
            11559732032986387107991004021392285783925812861821192530917403151452391805634,
            10857046999023057135944570762232829481370756359578518086990519993285655852781
        },
        {
            4082367875863433681332203403145435568316851327593401208105741076214120093531,
            8495653923123431417604973247489272438418190587263600148770280649306958101930
        },
        {0, 1},
        {0, 1}
    };

    static const FQ2 FQ2Zero = {0, 0};
    static const FQ2 FQ2One = {0, 1};

    static const FQ6 FQ6Zero = {
        FQ2Zero, FQ2Zero, FQ2Zero
    };

    static const FQ6 FQ6One = {
        FQ2Zero, FQ2Zero, FQ2One
    };

    static const FQ12 FQ12Zero = {FQ6Zero, FQ6Zero};
    static const FQ12 FQ12One = {FQ6Zero, FQ6One};

    // Curve field modulus:
    static const int P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Curve group modulus:
    static const int n = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // P - 2
    static const int Psub2 = 65000549695646603732796438742359905742825358107623003571877145026864184071781;

    // r3 is R^3 where R = 2^256 mod P.
    static const int r3 = 0x24ebbbb3a2529292df2ff66396b107a7388f899054f538a42af2dfb9324a5bb8;

    // Upper bound of the eGCD mod inverse loop:
    static const int UB = 368; 

    // xiToPMinus1Over6 is ξ^((p-1)/6) where ξ = i+9.
    static const FQ2 xiToPMinus1Over6 = {
        16469823323077808223889137241176536799009286646108169935659301613961712198316,
        8376118865763821496583973867626364092589906065868298776909617916018768340080
    };

    // xiTo2PMinus2Over3 is ξ^((2p-2)/3) where ξ = i+9.
    static const FQ2 xiTo2PMinus2Over3 = {
        19937756971775647987995932169929341994314640652964949448313374472400716661030,
        2581911344467009335267311115468803099551665605076196740867805258568234346338
    };

    // xiToPMinus1Over2 is ξ^((p-1)/2) where ξ = i+9.
    static const FQ2 xiToPMinus1Over2 = {
        3505843767911556378687030309984248845540243509899259641013678093033130930403,
        2821565182194536844548159561693502659359617185244120367078079554186484126554
    };

    // xiToPMinus1Over3 is ξ^((p-1)/3) where ξ = i+9.
    static const FQ2 xiToPMinus1Over3 = {
        10307601595873709700152284273816112264069230130616436755625194854815875713954,
        21575463638280843010398324269430826099269044274347216827212613867836435027261
    };

    // xiTo2PSquaredMinus2Over3 is ξ^((2p²-2)/3) where ξ = i+9 (a cubic root of unity, mod p).
    static const FQ xiTo2PSquaredMinus2Over3 = 2203960485148121921418603742825762020974279258880205651966;
    
    // xiToPSquaredMinus1Over3 is ξ^((p²-1)/3) where ξ = i+9.
    static const FQ xiToPSquaredMinus1Over3 = 21888242871839275220042445260109153167277707414472061641714758635765020556616;

    // xiToPSquaredMinus1Over6 is ξ^((1p²-1)/6) where ξ = i+9 (a cubic root of -1, mod p).
    static const FQ xiToPSquaredMinus1Over6 = 21888242871839275220042445260109153167277707414472061641714758635765020556617;

    static function modReduce(int k, int modulus) : int {
        int res = k % modulus;
        return (res < 0) ? res + modulus : res;
    }

    static function mulFQ2(FQ2 a, FQ2 b) : FQ2 {
        int tx = a.x * b.y;
        int t =  b.x * a.y;
        int tx_2 = tx + t;

        int ty = a.y * b.y;
        int t_2 = a.x * b.x;
        int ty_2 = ty - t_2;
        
        return {modReduce(tx_2, P), modReduce(ty_2, P)};
    }

    static function mulXiFQ2(FQ2 a) : FQ2 {
        // (xi+y)(i+3) = (9x+y)i+(9y-x)
        FQ tx = (a.x << 3) + a.x + a.y;
        FQ ty = (a.y << 3) + a.y - a.x;
        return {modReduce(tx, P), modReduce(ty, P)};
    }

    static function mulScalarFQ2(FQ2 a, int scalar) : FQ2 {
        return {
            modReduce(a.x * scalar, P),
            modReduce(a.y * scalar, P)
        };
    }

    static function addFQ2(FQ2 a, FQ2 b) : FQ2 {
        return {
            modReduce(a.x + b.x, P), 
            modReduce(a.y + b.y, P)
        };
    }

    static function subFQ2(FQ2 a, FQ2 b) : FQ2 {
        return {
            modReduce(a.x - b.x, P),
            modReduce(a.y - b.y, P)
        };
    }

    static function negFQ2(FQ2 a) : FQ2 {
        return {
            modReduce(a.x * -1, P), 
            modReduce(a.y * -1, P)
        };
    }

    static function conjugateFQ2(FQ2 a) : FQ2 {
        return {
            modReduce(a.x * -1, P), 
            modReduce(a.y, P)
        };
    }

    static function doubleFQ2(FQ2 a) : FQ2 {
        return {
            modReduce(a.x * 2, P),
            modReduce(a.y * 2, P)
        };
    }

    static function squareFQ2(FQ2 a) : FQ2 {
        int tx = a.y - a.x;
        int ty = a.x + a.y;
        int ty_2 = ty * tx;

        int tx_2 = (a.x * a.y) * 2;

        return {modReduce(tx_2, P), modReduce(ty_2, P)};
    }

    static function modInverseEGCD(int x, int n) : int {
        // The following script already does modular reduction at the start so there's no
        // need to normalize x before function call.
        asm {
            OP_2DUP OP_MOD OP_DUP OP_0 OP_LESSTHAN OP_IF OP_DUP OP_2 OP_PICK OP_ADD OP_ELSE OP_DUP OP_ENDIF OP_NIP OP_2 OP_ROLL OP_DROP
            OP_DUP OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
            OP_1 OP_0 OP_1
            loop(UB) {
                OP_FROMALTSTACK OP_FROMALTSTACK OP_2DUP OP_DUP OP_IF OP_TUCK OP_MOD OP_TOALTSTACK OP_TOALTSTACK OP_DIV OP_MUL OP_SUB OP_TUCK OP_ELSE OP_TOALTSTACK OP_TOALTSTACK OP_DROP OP_DROP OP_ENDIF
            }
            OP_FROMALTSTACK OP_FROMALTSTACK OP_DROP OP_DROP OP_DROP OP_FROMALTSTACK OP_SWAP OP_NIP
        }
    }

    static function inverseFQ2(FQ2 a) : FQ2 {
        int t2 = a.y * a.y; 
        int t1 = (a.x * a.x) + t2;

        int inv = modInverseEGCD(t1, P);

        int axNeg = a.x * -1;

        return {
            modReduce(axNeg * inv, P),
            modReduce(a.y * inv, P)
        };
    }

    static function mulFQ6(FQ6 a, FQ6 b) : FQ6 {
        // "Multiplication and Squaring on Pairing-Friendly Fields"
        // Section 4, Karatsuba method.
        // http://eprint.iacr.org/2006/471.pdf

        FQ2 v0 = mulFQ2(a.z, b.z);
        FQ2 v1 = mulFQ2(a.y, b.y);
        FQ2 v2 = mulFQ2(a.x, b.x);

        FQ2 t0 = addFQ2(a.x, a.y);
        FQ2 t1 = addFQ2(b.x, b.y);
        FQ2 tz = mulFQ2(t0, t1);

        tz = subFQ2(tz, v1);
        tz = subFQ2(tz, v2);
        tz = mulXiFQ2(tz);
        tz = addFQ2(tz, v0);

        t0 = addFQ2(a.y, a.z);
        t1 = addFQ2(b.y, b.z);
        
        FQ2 ty = mulFQ2(t0, t1);
        ty = subFQ2(ty, v0);
        ty = subFQ2(ty, v1);
        t0 = mulXiFQ2(v2);
        ty = addFQ2(ty, t0);

        t0 = addFQ2(a.x, a.z);
        t1 = addFQ2(b.x, b.z);
        FQ2 tx = mulFQ2(t0, t1);
        tx = subFQ2(tx, v0);
        tx = addFQ2(tx, v1);
        tx = subFQ2(tx, v2);

        return {tx, ty, tz};
    }

    static function doubleFQ6(FQ6 a) : FQ6 {
        return {
            doubleFQ2(a.x),
            doubleFQ2(a.y),
            doubleFQ2(a.z)
        };
    }

    static function mulScalarFQ6(FQ6 a, FQ2 scalar) : FQ6 {
        return {
            mulFQ2(a.x, scalar),
            mulFQ2(a.y, scalar),
            mulFQ2(a.z, scalar)
        };
    }

    static function addFQ6(FQ6 a, FQ6 b) : FQ6 {
        return {
            addFQ2(a.x, b.x),
            addFQ2(a.y, b.y),
            addFQ2(a.z, b.z)
        };
    }

    static function subFQ6(FQ6 a, FQ6 b) : FQ6 {
        return {
            subFQ2(a.x, b.x),
            subFQ2(a.y, b.y),
            subFQ2(a.z, b.z)
        };
    }

    static function negFQ6(FQ6 a) : FQ6 {
        return {
            negFQ2(a.x),
            negFQ2(a.y),
            negFQ2(a.z)
        };
    }

    static function squareFQ6(FQ6 a) : FQ6 {
        FQ2 v0 = squareFQ2(a.z);
        FQ2 v1 = squareFQ2(a.y);
        FQ2 v2 = squareFQ2(a.x);

        FQ2 c0 = addFQ2(a.x, a.y);
        c0 = squareFQ2(c0);
        c0 = subFQ2(c0, v1);
        c0 = subFQ2(c0, v2);
        c0 = mulXiFQ2(c0);
        c0 = addFQ2(c0, v0);

        FQ2 c1 = addFQ2(a.y, a.z);
        c1 = squareFQ2(c1);
        c1 = subFQ2(c1, v0);
        c1 = subFQ2(c1, v1);
        FQ2 xiV2 = mulXiFQ2(v2);
        c1 = addFQ2(c1, xiV2);

        FQ2 c2 = addFQ2(a.x, a.z);
        c2 = squareFQ2(c2);
        c2 = subFQ2(c2, v0);
        c2 = addFQ2(c2, v1);
        c2 = subFQ2(c2, v2);

        return {c2, c1, c0};
    }

    static function mulTauFQ6(FQ6 a) : FQ6 {
        // MulTau computes τ·(aτ²+bτ+c) = bτ²+cτ+aξ
        return {
            a.y,
            a.z,
            mulXiFQ2(a.x)
        };
    }

    static function inverseFQ6(FQ6 a) : FQ6 {
        // See "Implementing cryptographic pairings", M. Scott, section 3.2.
        // ftp://136.206.11.249/pub/crypto/pairings.pdf

        // Here we can give a short explanation of how it works: let j be a cubic root of
        // unity in GF(p²) so that 1+j+j²=0.
        // Then (xτ² + yτ + z)(xj²τ² + yjτ + z)(xjτ² + yj²τ + z)
        // = (xτ² + yτ + z)(Cτ²+Bτ+A)
        // = (x³ξ²+y³ξ+z³-3ξxyz) = F is an element of the base field (the norm).
        //
        // On the other hand (xj²τ² + yjτ + z)(xjτ² + yj²τ + z)
        // = τ²(y²-ξxz) + τ(ξx²-yz) + (z²-ξxy)
        //
        // So that's why A = (z²-ξxy), B = (ξx²-yz), C = (y²-ξxz)

        FQ2 A = squareFQ2(a.z);
        FQ2 t1 = mulFQ2(a.x, a.y);
        t1 = mulXiFQ2(t1);
        A = subFQ2(A, t1);
        
        FQ2 B = squareFQ2(a.x);
        B = mulXiFQ2(B);
        t1 = mulFQ2(a.y, a.z);
        B = subFQ2(B, t1);

        FQ2 C = squareFQ2(a.y);
        t1 = mulFQ2(a.x, a.z);
        C = subFQ2(C, t1);
        
        FQ2 F = mulFQ2(C, a.y);
        F = mulXiFQ2(F);
        t1 = mulFQ2(A, a.z);
        F = addFQ2(F, t1);
        t1 = mulFQ2(B, a.x);
        t1 = mulXiFQ2(t1);
        F = addFQ2(F, t1);

        F = inverseFQ2(F);

        return {
            mulFQ2(C, F),
            mulFQ2(B, F),
            mulFQ2(A, F)
        };
    }

    static function mulScalarFQ12(FQ12 a, FQ6 b) : FQ12 {
        return {
            mulFQ6(a.x, b),
            mulFQ6(a.y, b)
        };
    }

    static function inverseFQ12(FQ12 a) : FQ12 {
        // See "Implementing cryptographic pairings", M. Scott, section 3.2.
        // ftp://136.206.11.249/pub/crypto/pairings.pdf

        FQ6 t1 = squareFQ6(a.x);
        FQ6 t2 = squareFQ6(a.y);
        FQ6 t1_2 = mulTauFQ6(t1);
        FQ6 t1_3 = subFQ6(t2, t1_2);
        FQ6 t2_2 = inverseFQ6(t1_3);

        FQ12 e = {
            negFQ6(a.x),
            a.y
        };
        
        return mulScalarFQ12(e, t2_2);
    }

    static function mulFQ12(FQ12 a, FQ12 b) : FQ12 {
        FQ6 tx = mulFQ6(a.x, b.y);
        FQ6 t = mulFQ6(b.x, a.y);
        FQ6 tx2 = addFQ6(tx, t);

        FQ6 ty = mulFQ6(a.y, b.y);
        FQ6 t2 = mulFQ6(a.x, b.x);
        FQ6 t3 = mulTauFQ6(t2);
        
        return {tx2, addFQ6(ty, t3)};
    }

    static function frobeniusFQ6(FQ6 a) : FQ6 {
        return {
            mulFQ2(conjugateFQ2(a.x), xiTo2PMinus2Over3),
            mulFQ2(conjugateFQ2(a.y), xiToPMinus1Over3),
            conjugateFQ2(a.z)
        };
    }

    static function frobeniusP2FQ6(FQ6 a) : FQ6 {
        // FrobeniusP2 computes (xτ²+yτ+z)^(p²) = xτ^(2p²) + yτ^(p²) + z
        return {
            // τ^(2p²) = τ²τ^(2p²-2) = τ²ξ^((2p²-2)/3)
            mulScalarFQ2(a.x, xiTo2PSquaredMinus2Over3),
            // τ^(p²) = ττ^(p²-1) = τξ^((p²-1)/3)
            mulScalarFQ2(a.y, xiToPSquaredMinus1Over3),
            a.z
        };
    }

    static function mulGFP(FQ6 a, int b) : FQ6 {
        return {
            mulScalarFQ2(a.x, b),
            mulScalarFQ2(a.y, b),
            mulScalarFQ2(a.z, b)
        };
    }

    static function conjugateFQ12(FQ12 a) : FQ12 {
        return {
            negFQ6(a.x),
            a.y
        };
    }

    static function frobeniusFQ12(FQ12 a) : FQ12 {
        // Frobenius computes (xω+y)^p = x^p ω·ξ^((p-1)/6) + y^p
        return {
            mulScalarFQ6(frobeniusFQ6(a.x), xiToPMinus1Over6),
            frobeniusFQ6(a.y)
        };
    }

    static function frobeniusP2FQ12(FQ12 a) : FQ12 {
        // FrobeniusP2 computes (xω+y)^p² = x^p² ω·ξ^((p²-1)/6) + y^p²
        return {
            mulGFP(frobeniusP2FQ6(a.x), xiToPSquaredMinus1Over6),
            frobeniusP2FQ6(a.y)
        };
    }

    static function squareFQ12(FQ12 a) : FQ12 {
        // Complex squaring algorithm
        FQ6 v0 = mulFQ6(a.x, a.y);

        FQ6 t = mulTauFQ6(a.x);
        FQ6 t2 = addFQ6(a.y, t);
        FQ6 ty = addFQ6(a.x, a.y);
        FQ6 ty2 = mulFQ6(ty, t2);
        FQ6 ty3 = subFQ6(ty2, v0);
        FQ6 t3 = mulTauFQ6(v0);

        FQ6 ty4 = subFQ6(ty3, t3);

        return {
            doubleFQ6(v0),
            ty4
        };
    }

    static function expFQ12_u(FQ12 a) : FQ12 {
        // u is the BN parameter that determines the prime.
        // u = 4965661367192848881;

        FQ12 sum = FQ12One;

        // Unrolled loop. Reference impl.:
        // https://github.com/ethereum/go-ethereum/blob/bd6879ac518431174a490ba42f7e6e822dcb3ee1/crypto/bn256/google/gfp12.go#L138
        FQ12 sum0 = squareFQ12(sum);
        FQ12 sum1 = mulFQ12(sum0, a);
        FQ12 sum2 = squareFQ12(sum1);
        FQ12 sum3 = squareFQ12(sum2);
        FQ12 sum4 = squareFQ12(sum3);
        FQ12 sum5 = squareFQ12(sum4);
        FQ12 sum6 = mulFQ12(sum5, a);
        FQ12 sum7 = squareFQ12(sum6);
        FQ12 sum8 = squareFQ12(sum7);
        FQ12 sum9 = squareFQ12(sum8);
        FQ12 sum10 = mulFQ12(sum9, a);
        FQ12 sum11 = squareFQ12(sum10);
        FQ12 sum12 = mulFQ12(sum11, a);
        FQ12 sum13 = squareFQ12(sum12);
        FQ12 sum14 = mulFQ12(sum13, a);
        FQ12 sum15 = squareFQ12(sum14);
        FQ12 sum16 = squareFQ12(sum15);
        FQ12 sum17 = mulFQ12(sum16, a);
        FQ12 sum18 = squareFQ12(sum17);
        FQ12 sum19 = squareFQ12(sum18);
        FQ12 sum20 = squareFQ12(sum19);
        FQ12 sum21 = mulFQ12(sum20, a);
        FQ12 sum22 = squareFQ12(sum21);
        FQ12 sum23 = mulFQ12(sum22, a);
        FQ12 sum24 = squareFQ12(sum23);
        FQ12 sum25 = squareFQ12(sum24);
        FQ12 sum26 = squareFQ12(sum25);
        FQ12 sum27 = mulFQ12(sum26, a);
        FQ12 sum28 = squareFQ12(sum27);
        FQ12 sum29 = squareFQ12(sum28);
        FQ12 sum30 = squareFQ12(sum29);
        FQ12 sum31 = mulFQ12(sum30, a);
        FQ12 sum32 = squareFQ12(sum31);
        FQ12 sum33 = squareFQ12(sum32);
        FQ12 sum34 = mulFQ12(sum33, a);
        FQ12 sum35 = squareFQ12(sum34);
        FQ12 sum36 = squareFQ12(sum35);
        FQ12 sum37 = mulFQ12(sum36, a);
        FQ12 sum38 = squareFQ12(sum37);
        FQ12 sum39 = mulFQ12(sum38, a);
        FQ12 sum40 = squareFQ12(sum39);
        FQ12 sum41 = squareFQ12(sum40);
        FQ12 sum42 = mulFQ12(sum41, a);
        FQ12 sum43 = squareFQ12(sum42);
        FQ12 sum44 = squareFQ12(sum43);
        FQ12 sum45 = squareFQ12(sum44);
        FQ12 sum46 = squareFQ12(sum45);
        FQ12 sum47 = mulFQ12(sum46, a);
        FQ12 sum48 = squareFQ12(sum47);
        FQ12 sum49 = squareFQ12(sum48);
        FQ12 sum50 = squareFQ12(sum49);
        FQ12 sum51 = mulFQ12(sum50, a);
        FQ12 sum52 = squareFQ12(sum51);
        FQ12 sum53 = squareFQ12(sum52);
        FQ12 sum54 = mulFQ12(sum53, a);
        FQ12 sum55 = squareFQ12(sum54);
        FQ12 sum56 = squareFQ12(sum55);
        FQ12 sum57 = squareFQ12(sum56);
        FQ12 sum58 = mulFQ12(sum57, a);
        FQ12 sum59 = squareFQ12(sum58);
        FQ12 sum60 = mulFQ12(sum59, a);
        FQ12 sum61 = squareFQ12(sum60);
        FQ12 sum62 = squareFQ12(sum61);
        FQ12 sum63 = mulFQ12(sum62, a);
        FQ12 sum64 = squareFQ12(sum63);
        FQ12 sum65 = squareFQ12(sum64);
        FQ12 sum66 = squareFQ12(sum65);
        FQ12 sum67 = mulFQ12(sum66, a);
        FQ12 sum68 = squareFQ12(sum67);
        FQ12 sum69 = squareFQ12(sum68);
        FQ12 sum70 = squareFQ12(sum69);
        FQ12 sum71 = squareFQ12(sum70);
        FQ12 sum72 = squareFQ12(sum71);
        FQ12 sum73 = mulFQ12(sum72, a);
        FQ12 sum74 = squareFQ12(sum73);
        FQ12 sum75 = squareFQ12(sum74);
        FQ12 sum76 = squareFQ12(sum75);
        FQ12 sum77 = mulFQ12(sum76, a);
        FQ12 sum78 = squareFQ12(sum77);
        FQ12 sum79 = mulFQ12(sum78, a);
        FQ12 sum80 = squareFQ12(sum79);
        FQ12 sum81 = mulFQ12(sum80, a);
        FQ12 sum82 = squareFQ12(sum81);
        FQ12 sum83 = mulFQ12(sum82, a);
        FQ12 sum84 = squareFQ12(sum83);
        FQ12 sum85 = mulFQ12(sum84, a);
        FQ12 sum86 = squareFQ12(sum85);
        FQ12 sum87 = squareFQ12(sum86);
        FQ12 sum88 = squareFQ12(sum87);
        FQ12 sum89 = squareFQ12(sum88);
        FQ12 sum90 = mulFQ12(sum89, a);
        
        return sum90;

    }

    static function expFQ12(FQ12 a, int power) : FQ12 {
        FQ12 sum = FQ12One;
        FQ12 t = FQ12One;

        bytes mb = reverseBytes(num2bin(power, S), S);
        bool firstOne = false;

        loop (CURVE_BITS_P8) : i {
            if (firstOne) {
                t = squareFQ12(sum);
            }

            if ((mb & (mask << ((CURVE_BITS_P8 - 1) - i))) != zero) {
                firstOne = true;
                sum = mulFQ12(t, a);
            } else {
                sum = t;
            }
        }

        return sum;
    }

    // ----------------------------------------------------

    static function doubleG1Point(G1Point a) : G1Point {
        CurvePoint res = doubleCurvePoint(
                createCurvePoint(a)
        );
        
        return getG1Point(res);
    }

    static function doubleCurvePoint(CurvePoint a) : CurvePoint {
        // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
        CurvePoint res = {0, 0, 0, 0};

        int A = modReduce(a.x * a.x, P);
        int B = modReduce(a.y * a.y, P);
        int C = modReduce(B * B, P);

        int t = a.x + B;
        int t2 = modReduce(t * t, P);
        t = t2 - A;
        t2 = t - C;

        int d = t2 * 2;
        t = A * 2;
        int e = t + A;
        int f = modReduce(e * e, P);

        t = d * 2;
        res.x = f - t;

        t = C * 2;
        t2 = t * 2;
        t = t2 * 2;
        res.y = d - res.x;
        t2 = modReduce(e * res.y, P);
        res.y = t2 - t;

        //int prod = res.y * a.z;
        //if (a.t != 0) {
        //    prod = a.y * a.z;
        //}
        //res.z = modReduce(prod, P) * 2;

        int prod = a.y * a.z;
        res.z = modReduce(prod, P) * 2;

        return res;
    }

    static function addG1Points(G1Point a, G1Point b) : G1Point {
        CurvePoint res = addCurvePoints(
                createCurvePoint(a),
                createCurvePoint(b)
        );
        
        return getG1Point(res);
    }

    static function addCurvePoints(CurvePoint a, CurvePoint b) : CurvePoint {
        // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3
        CurvePoint res = {0, 0, 0, 0};
        
        if (a.z == 0) {
            res = b;
        } else if (b.z == 0) {
            res = a;
        } else {
            // Normalize the points by replacing a = [x1:y1:z1] and b = [x2:y2:z2]
            // by [u1:s1:z1·z2] and [u2:s2:z1·z2]
            // where u1 = x1·z2², s1 = y1·z2³ and u1 = x2·z1², s2 = y2·z1³
            
            int z12 = modReduce(a.z * a.z, P);
            int z22 = modReduce(b.z * b.z, P);
            
            int u1 = modReduce(a.x * z22, P);
            int u2 = modReduce(b.x * z12, P);

            int t = modReduce(b.z * z22, P);
            int s1 = modReduce(a.y * t, P);

            t = modReduce(a.z * z12, P);
            int s2 = modReduce(b.y * t, P);

            // Compute x = (2h)²(s²-u1-u2)
            // where s = (s2-s1)/(u2-u1) is the slope of the line through
            // (u1,s1) and (u2,s2). The extra factor 2h = 2(u2-u1) comes from the value of z below.
            // This is also:
            // 4(s2-s1)² - 4h²(u1+u2) = 4(s2-s1)² - 4h³ - 4h²(2u1)
            //                        = r² - j - 2v
            // with the notations below.

            int h = u2 - u1;
            bool xEqual = h == 0;

            t = h * 2;
            // i = 4h²
            int i = modReduce(t * t, P);
            // j = 4h³
            int j = modReduce(h * i, P);

            t = s2 - s1;
            bool yEqual = t == 0;

            if (xEqual && yEqual) {
                res = doubleCurvePoint(a);
            } else {
                int r = t + t;
                int v = modReduce(u1 * i, P);

                // t4 = 4(s2-s1)²
                int t4 = modReduce(r * r, P);
                int t6 = t4 - j;
                t = v * 2;

                res.x = t6 - t;

                // Set y = -(2h)³(s1 + s*(x/4h²-u1))
                // This is also
                // y = - 2·s1·j - (s2-s1)(2x - 2i·u1) = r(v-x) - 2·s1·j
                t = v - res.x;
                t4 = modReduce(s1 * j, P);
                t6 = t4 * 2;
                t4 = modReduce(r * t, P);
                res.y = t4 - t6;
                
                // Set z = 2(u2-u1)·z1·z2 = 2h·z1·z2
                t = a.z + b.z;
                t4 = modReduce(t * t, P);
                t = t4 - z12;
                t4 = t - z22;
                res.z = modReduce(t4 * h, P);
            }
        }

        return res;
    }

    static function mulG1Point(G1Point a, int m) : G1Point {
        CurvePoint res = mulCurvePoint(
                createCurvePoint(a),
                m
        );
        
        return getG1Point(res);
    }
        
    static function mulCurvePoint(CurvePoint a, int m) : CurvePoint {
       CurvePoint res = {0, 1, 0, 0};

        if (m != 0) {
            // Double and add method.
            // Lowest bit to highest.
            CurvePoint t =   {0, 0, 0, 0};
            CurvePoint sum = {0, 0, 0, 0};

            bytes mb = reverseBytes(num2bin(m, S), S);
            bool firstOne = false;

            loop (CURVE_BITS_P8) : i {
                if (firstOne) {
                    t = doubleCurvePoint(sum);
                }

                if ((mb & (mask << ((CURVE_BITS_P8 - 1) - i))) != zero) {
                    firstOne = true;
                    sum = addCurvePoints(t, a);
                } else {
                    sum = t;
                }
            }

            res = sum;
        }

        return res;
    }

    static function makeAffineCurvePoint(CurvePoint a) : CurvePoint {
        // MakeAffine converts a to affine form. If c is ∞, then it sets
        // a to 0 : 1 : 0.

        CurvePoint res = a;
        if (a.z != 1) {
            if (a.z == 0) {
                res = {0, 1, 0, 0};
            } else {
                FQ zInv = modInverseEGCD(a.z, P);
                FQ t = modReduce(a.y * zInv, P);
                FQ zInv2 = modReduce(zInv * zInv, P);
                FQ ay = modReduce(t * zInv2, P);
                FQ ax = modReduce(a.x * zInv2, P);
                
                res = {ax, ay, 1, 1};
            }
        }

        return res;
    }

    static function negCurvePoint(CurvePoint a) : CurvePoint {
        return {
            a.x,
            -a.y,
            a.z,
            0
        };
    }

    static function isInfCurvePoint(CurvePoint a) : bool {
        return a.z == 0;
    }

    static function createCurvePoint(G1Point ccp) : CurvePoint {
        CurvePoint res = {0, 1, 0, 0};
        if (ccp != {0, 1}) {
            res = {ccp.x, ccp.y, 1, 1};
        }
        return res;
    }

    static function getG1Point(CurvePoint cp) : G1Point {
        CurvePoint acp = makeAffineCurvePoint(cp);
        return {acp.x, acp.y};
    }

    // ----------------------------------------------------

    static function doubleG2Point(G2Point a) : G2Point {
        TwistPoint res = doubleTwistPoint(
                createTwistPoint(a)
        );
        
        return getG2Point(res);
    }

    static function doubleTwistPoint(TwistPoint a) : TwistPoint {
        // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
        TwistPoint res = {FQ2Zero, FQ2Zero, FQ2Zero, FQ2Zero};

        FQ2 A = squareFQ2(a.x);
        FQ2 B = squareFQ2(a.y);
        FQ2 C = squareFQ2(B);

        FQ2 t = addFQ2(a.x, B);
        FQ2 t2 = squareFQ2(t);
        t = subFQ2(t2, A);
        t2 = subFQ2(t, C);

        FQ2 d = mulScalarFQ2(t2, 2);
        t = mulScalarFQ2(A, 2);
        FQ2 e = addFQ2(t, A);
        FQ2 f = squareFQ2(e);

        t = mulScalarFQ2(d, 2);
        res.x = subFQ2(f, t);

        t = mulScalarFQ2(C, 2);
        t2 = mulScalarFQ2(t, 2);
        t = mulScalarFQ2(t2, 2);
        res.y = subFQ2(d, res.x);
        t2 = mulFQ2(e, res.y);
        res.y = subFQ2(t2, t);

        res.z = mulScalarFQ2(mulFQ2(a.y, a.z), 2);

        return res;
    }

    static function addG2Points(G2Point a, G2Point b) : G2Point {
        TwistPoint res = addTwistPoints(
                createTwistPoint(a),
                createTwistPoint(b)
        );
        
        return getG2Point(res);
    }

    static function addTwistPoints(TwistPoint a, TwistPoint b) : TwistPoint {
        TwistPoint res = {FQ2Zero, FQ2Zero, FQ2Zero, a.t};
        
        if (a.z == FQ2Zero) {
            res = b;
        } else if (b.z == FQ2Zero) {
            res = a;
        } else {
            // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3

            // Normalize the points by replacing a = [x1:y1:z1] and b = [x2:y2:z2]
            // by [u1:s1:z1·z2] and [u2:s2:z1·z2]
            // where u1 = x1·z2², s1 = y1·z2³ and u1 = x2·z1², s2 = y2·z1³
            
            FQ2 z12 = squareFQ2(a.z);
            FQ2 z22 = squareFQ2(b.z);
            
            FQ2 u1 = mulFQ2(a.x, z22);
            FQ2 u2 = mulFQ2(b.x, z12);

            FQ2 t = mulFQ2(b.z, z22);
            FQ2 s1 = mulFQ2(a.y, t);

            t = mulFQ2(a.z, z12);
            FQ2 s2 = mulFQ2(b.y, t);

            // Compute x = (2h)²(s²-u1-u2)
            // where s = (s2-s1)/(u2-u1) is the slope of the line through
            // (u1,s1) and (u2,s2). The extra factor 2h = 2(u2-u1) comes from the value of z below.
            // This is also:
            // 4(s2-s1)² - 4h²(u1+u2) = 4(s2-s1)² - 4h³ - 4h²(2u1)
            //                        = r² - j - 2v
            // with the notations below.

            FQ2 h = subFQ2(u2, u1);
            bool xEqual = h == FQ2Zero;

            t = mulScalarFQ2(h, 2);
            // i = 4h²
            FQ2 i = squareFQ2(t);
            // j = 4h³
            FQ2 j = mulFQ2(h, i);

            t = subFQ2(s2, s1);
            bool yEqual = t == FQ2Zero;
            if (xEqual && yEqual) {
                res = doubleTwistPoint(a);
            } else {
                FQ2 r = mulScalarFQ2(t, 2);
                FQ2 v = mulFQ2(u1, i);

                // t4 = 4(s2-s1)²
                FQ2 t4 = squareFQ2(r);
                FQ2 t6 = subFQ2(t4, j);
                t = mulScalarFQ2(v, 2);

                res.x = subFQ2(t6, t);

                // Set y = -(2h)³(s1 + s*(x/4h²-u1))
                // This is also
                // y = - 2·s1·j - (s2-s1)(2x - 2i·u1) = r(v-x) - 2·s1·j
                t = subFQ2(v, res.x);
                t4 = mulFQ2(s1, j);
                t6 = mulScalarFQ2(t4, 2);
                t4 = mulFQ2(r, t);
                res.y = subFQ2(t4, t6);
                
                // Set z = 2(u2-u1)·z1·z2 = 2h·z1·z2
                t = addFQ2(a.z, b.z);
                t4 = squareFQ2(t);
                t = subFQ2(t4, z12);
                t4 = subFQ2(t, z22);
                res.z = mulFQ2(t4, h);
            }
        }

        return res;
    }

    static function mulG2Point(G2Point a, int n) : G2Point {
        TwistPoint res = mulTwistPoint(
                createTwistPoint(a),
                n
        );
        
        return getG2Point(res);
    }

    static function mulTwistPoint(TwistPoint a, int m) : TwistPoint {
        // Double and add method.
        // Lowest bit to highest.
        TwistPoint t =   {FQ2Zero, FQ2Zero, FQ2Zero, FQ2Zero};
        TwistPoint sum = {FQ2Zero, FQ2Zero, FQ2Zero, FQ2Zero};

        bytes mb = reverseBytes(num2bin(m, S), S);
        bool firstOne = false;

        loop (CURVE_BITS_P8) : i {
            if (firstOne) {
                t = doubleTwistPoint(sum);
            }

            if ((mb & (mask << ((CURVE_BITS_P8 - 1) - i))) != zero) {
                firstOne = true;
                sum = addTwistPoints(t, a);
            } else {
                sum = t;
            }
        }

        return sum;
    }

    static function makeAffineTwistPoint(TwistPoint a) : TwistPoint {
        TwistPoint res = a; 
        if (a.z != {0, 1}) {
            if (a.z == FQ2Zero) {
                res = {
                    FQ2Zero,
                    FQ2One,
                    FQ2Zero,
                    FQ2Zero
                };
            } else {
                FQ2 zInv = inverseFQ2(a.z);
                FQ2 t = mulFQ2(a.y, zInv);
                FQ2 zInv2 = squareFQ2(zInv);
                res.y = mulFQ2(t, zInv2);
                t = mulFQ2(a.x, zInv2);
                res.x = t;
                res.z = {0, 1};
                res.t = {0, 1};
            }
        }

        return res;
    }

    static function negTwistPoint(TwistPoint a) : TwistPoint {
        return {
            a.x,
            subFQ2(FQ2Zero, a.y),
            a.z,
            FQ2Zero
        };
    }

    static function isInfTwistPoint(TwistPoint a) : bool {
        return a.z == FQ2Zero;
    }

    static function createTwistPoint(G2Point ctp) : TwistPoint {
        TwistPoint res = {FQ2Zero, FQ2One, FQ2Zero, FQ2Zero};
        if (ctp != {FQ2Zero, FQ2One}) {
            res = {{ctp.x.y, ctp.x.x}, {ctp.y.y, ctp.y.x}, FQ2One, FQ2One}; 
        }
        return res;
    }

    static function getG2Point(TwistPoint tp) : G2Point {
        TwistPoint atp = makeAffineTwistPoint(tp);
        return {atp.x, atp.y};
    }

}
"#;



let pairing_lib = r#"



struct LineFuncRes {
    FQ2 a;
    FQ2 b;
    FQ2 c;
    TwistPoint rOut;
}


library BN256Pairing {

    static function lineFuncAdd(TwistPoint r, TwistPoint p, CurvePoint q, FQ2 r2) : LineFuncRes {
        // See the mixed addition algorithm from "Faster Computation of the
        // Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf

        FQ2 B = BN256.mulFQ2(p.x, r.t);
        FQ2 D = BN256.addFQ2(p.y, r.z);
        D = BN256.squareFQ2(D);
        D = BN256.subFQ2(D, r2);
        D = BN256.subFQ2(D, r.t);
        D = BN256.mulFQ2(D, r.t);

        FQ2 H = BN256.subFQ2(B, r.x);
        FQ2 I = BN256.squareFQ2(H);

        FQ2 E = BN256.addFQ2(I, I);
        E = BN256.addFQ2(E, E);

        FQ2 J = BN256.mulFQ2(H, E);

        FQ2 L1 = BN256.subFQ2(D, r.y);
        L1 = BN256.subFQ2(L1, r.y);

        FQ2 V = BN256.mulFQ2(r.x, E);

        FQ2 rOutX = BN256.squareFQ2(L1);
        rOutX = BN256.subFQ2(rOutX, J);
        rOutX = BN256.subFQ2(rOutX, V);
        rOutX = BN256.subFQ2(rOutX, V);

        FQ2 rOutZ = BN256.addFQ2(r.z, H);
        rOutZ = BN256.squareFQ2(rOutZ);
        rOutZ = BN256.subFQ2(rOutZ, r.t);
        rOutZ = BN256.subFQ2(rOutZ, I);

        FQ2 t = BN256.subFQ2(V, rOutX);
        t = BN256.mulFQ2(t, L1);
        FQ2 t2 = BN256.mulFQ2(r.y, J);
        t2 = BN256.addFQ2(t2, t2);
        FQ2 rOutY = BN256.subFQ2(t, t2);

        FQ2 rOutT = BN256.squareFQ2(rOutZ);

        t = BN256.addFQ2(p.y, rOutZ);
        t = BN256.squareFQ2(t);
        t = BN256.subFQ2(t, r2);
        t = BN256.subFQ2(t, rOutT);

        t2 = BN256.mulFQ2(L1, p.x);
        t2 = BN256.addFQ2(t2, t2);
        FQ2 a = BN256.subFQ2(t2, t);

        FQ2 c = BN256.mulScalarFQ2(rOutZ, q.y);
        c = BN256.addFQ2(c, c);

        FQ2 b = BN256.subFQ2(BN256.FQ2Zero, L1);
        b = BN256.mulScalarFQ2(b, q.x);
        b = BN256.addFQ2(b, b);

        TwistPoint rOut = {
            rOutX, rOutY, rOutZ, rOutT
        };

        return {a, b, c, rOut};
    }

    static function lineFuncDouble(TwistPoint r, CurvePoint q) : LineFuncRes {
        // See the doubling algorithm for a=0 from "Faster Computation of the
        // Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf

        FQ2 A = BN256.squareFQ2(r.x);
        FQ2 B = BN256.squareFQ2(r.y);
        FQ2 C = BN256.squareFQ2(B);

        FQ2 D = BN256.addFQ2(r.x, B);
        D = BN256.squareFQ2(D);
        D = BN256.subFQ2(D, A);
        D = BN256.subFQ2(D, C);
        D = BN256.addFQ2(D, D);

        FQ2 E = BN256.addFQ2(A, A);
        E = BN256.addFQ2(E, A);

        FQ2 G = BN256.squareFQ2(E);

        FQ2 rOutX = BN256.subFQ2(G, D);
        rOutX = BN256.subFQ2(rOutX, D);

        FQ2 rOutZ = BN256.addFQ2(r.y, r.z);
        rOutZ = BN256.squareFQ2(rOutZ);
        rOutZ = BN256.subFQ2(rOutZ, B);
        rOutZ = BN256.subFQ2(rOutZ, r.t);

        FQ2 rOutY = BN256.subFQ2(D, rOutX);
        rOutY = BN256.mulFQ2(rOutY, E);
        FQ2 t = BN256.addFQ2(C, C);
        t = BN256.addFQ2(t, t);
        t = BN256.addFQ2(t, t);
        rOutY = BN256.subFQ2(rOutY, t);

        FQ2 rOutT = BN256.squareFQ2(rOutZ);

        t = BN256.mulFQ2(E, r.t);
        t = BN256.addFQ2(t, t);
        FQ2 b = BN256.subFQ2(BN256.FQ2Zero, t);
        b = BN256.mulScalarFQ2(b, q.x);

        FQ2 a = BN256.addFQ2(r.x, E);
        a = BN256.squareFQ2(a);
        a = BN256.subFQ2(a, A);
        a = BN256.subFQ2(a, G);
        t = BN256.addFQ2(B, B);
        t = BN256.addFQ2(t, t);
        a = BN256.subFQ2(a, t);

        FQ2 c = BN256.mulFQ2(rOutZ, r.t);
        c = BN256.addFQ2(c, c);
        c = BN256.mulScalarFQ2(c, q.y);

        TwistPoint rOut = {
            rOutX, rOutY, rOutZ, rOutT
        };

        return {a, b, c, rOut};
    }

    static function mulLine(FQ12 ret, FQ2 a, FQ2 b, FQ2 c) : FQ12 {
        FQ6 a2 = {BN256.FQ2Zero, a, b};
        a2 = BN256.mulFQ6(a2, ret.x);
        FQ6 t3 = BN256.mulScalarFQ6(ret.y, c);

        FQ2 t = BN256.addFQ2(b, c);
        FQ6 t2 = {BN256.FQ2Zero, a, t};

        FQ6 resX = BN256.addFQ6(ret.x, ret.y);
        FQ6 resY = t3;

        resX = BN256.mulFQ6(resX, t2);
        resX = BN256.subFQ6(resX, a2);
        resX = BN256.subFQ6(resX, resY);
        a2 = BN256.mulTauFQ6(a2);
        resY = BN256.addFQ6(resY, a2);

        return {resX, resY};
    }

    static function miller(TwistPoint q, CurvePoint p) : FQ12 {
        FQ12 ret = BN256.FQ12One;

        TwistPoint aAffine = BN256.makeAffineTwistPoint(q);
        CurvePoint bAffine = BN256.makeAffineCurvePoint(p);

        TwistPoint minusA = BN256.negTwistPoint(aAffine);

        TwistPoint r = aAffine;

        FQ2 r2 = BN256.squareFQ2(aAffine.y);

        // sixuPlus2NAF is 6u+2 in non-adjacent form.
        // Unrolled loop to get rid of in-loop branching. Reference impl.:
        // https://github.com/ethereum/go-ethereum/blob/bd6879ac518431174a490ba42f7e6e822dcb3ee1/crypto/bn256/google/optate.go#L213
        // var sixuPlus2NAF = {}int8{0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0,
        //                           0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0, 1, 1,
        //                           1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1,
        //                           1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, 1, 1}
        
        //---- 1
        LineFuncRes lfr = lineFuncDouble(r, bAffine);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- -1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, minusA, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- -1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, minusA, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- -1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, minusA, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- -1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, minusA, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- -1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, minusA, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- -1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, minusA, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- -1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, minusA, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- -1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, minusA, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 1
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        lfr = lineFuncAdd(r, aAffine, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;
        //---- 0
        lfr = lineFuncDouble(r, bAffine);
        ret = BN256.squareFQ12(ret);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        // In order to calculate Q1 we have to convert q from the sextic twist
        // to the full GF(p^12) group, apply the Frobenius there, and convert
        // back.
        //
        // The twist isomorphism is (x', y') -> (xω², yω³). If we consider just
        // x for a moment, then after applying the Frobenius, we have x̄ω^(2p)
        // where x̄ is the conjugate of x. If we are going to apply the inverse
        // isomorphism we need a value with a single coefficient of ω² so we
        // rewrite this as x̄ω^(2p-2)ω². ξ⁶ = ω and, due to the construction of
        // p, 2p-2 is a multiple of six. Therefore we can rewrite as
        // x̄ξ^((p-1)/3)ω² and applying the inverse isomorphism eliminates the
        // ω².
        //
        // A similar argument can be made for the y value.

        FQ2 q1x = BN256.conjugateFQ2(aAffine.x);
        q1x = BN256.mulFQ2(q1x, BN256.xiToPMinus1Over3);
        FQ2 q1y = BN256.conjugateFQ2(aAffine.y);
        q1y = BN256.mulFQ2(q1y, BN256.xiToPMinus1Over2);

        TwistPoint q1 = {
            q1x, q1y, {0, 1}, {0, 1}
        };

        // For Q2 we are applying the p² Frobenius. The two conjugations cancel
        // out and we are left only with the factors from the isomorphism. In
        // the case of x, we end up with a pure number which is why
        // xiToPSquaredMinus1Over3 is ∈ GF(p). With y we get a factor of -1. We
        // ignore this to end up with -Q2.

        FQ2 minusQ2x = BN256.mulScalarFQ2(aAffine.x, BN256.xiToPSquaredMinus1Over3);
        TwistPoint minusQ2 = {
            minusQ2x, aAffine.y, {0, 1}, {0, 1}
        };

        r2 = BN256.squareFQ2(q1.y);
        lfr = lineFuncAdd(r, q1, bAffine, r2);
        ret = mulLine(ret, lfr.a, lfr.b, lfr.c);
        r = lfr.rOut;

        r2 = BN256.squareFQ2(minusQ2.y);
        lfr = lineFuncAdd(r, minusQ2, bAffine, r2);
        return mulLine(ret, lfr.a, lfr.b, lfr.c);
    }

    static function finalExponentiation(FQ12 in) : FQ12 {
        FQ12 t1 = {
            BN256.negFQ6(in.x),
            in.y
        }; 

        FQ12 inv = BN256.inverseFQ12(in);
        t1 = BN256.mulFQ12(t1, inv);

        FQ12 t2 = BN256.frobeniusP2FQ12(t1);
        t1 = BN256.mulFQ12(t1, t2);

        FQ12 fp = BN256.frobeniusFQ12(t1);
        FQ12 fp2 = BN256.frobeniusP2FQ12(t1);
        FQ12 fp3 = BN256.frobeniusFQ12(fp2);

        FQ12 fu = BN256.expFQ12_u(t1);
        FQ12 fu2 = BN256.expFQ12_u(fu);
        FQ12 fu3 = BN256.expFQ12_u(fu2);

        FQ12 y3 = BN256.frobeniusFQ12(fu);
        FQ12 fu2p = BN256.frobeniusFQ12(fu2);
        FQ12 fu3p = BN256.frobeniusFQ12(fu3);
        FQ12 y2 = BN256.frobeniusP2FQ12(fu2);

        FQ12 y0 = BN256.mulFQ12(fp, fp2);
        y0 = BN256.mulFQ12(y0, fp3);

        FQ12 y1 = BN256.conjugateFQ12(t1);
        FQ12 y5 = BN256.conjugateFQ12(fu2);
        y3 = BN256.conjugateFQ12(y3);
        FQ12 y4 = BN256.mulFQ12(fu ,fu2p);
        y4 = BN256.conjugateFQ12(y4);

        FQ12 y6 = BN256.mulFQ12(fu3, fu3p);
        y6 = BN256.conjugateFQ12(y6);

        FQ12 t0 = BN256.squareFQ12(y6);
        t0 = BN256.mulFQ12(t0, y4);
        t0 = BN256.mulFQ12(t0, y5);
        t1 = BN256.mulFQ12(y3, y5);
        t1 = BN256.mulFQ12(t1, t0);
        t0 = BN256.mulFQ12(t0, y2);
        t1 = BN256.squareFQ12(t1);
        t1 = BN256.mulFQ12(t1, t0);
        t1 = BN256.squareFQ12(t1);
        t0 = BN256.mulFQ12(t1, y1);
        t1 = BN256.mulFQ12(t1, y0);
        t0 = BN256.squareFQ12(t0);
        t0 = BN256.mulFQ12(t0, t1);

        return t0;
    }

    static function pairInternal(CurvePoint g1, TwistPoint g2) : FQ12 {
        FQ12 e = miller(g2, g1);
        FQ12 ret = finalExponentiation(e);

        if (BN256.isInfTwistPoint(g2) || BN256.isInfCurvePoint(g1)) {
            ret = BN256.FQ12One;
        }

        return ret;
    }

    static function pairCheckP4Internal(
            CurvePoint a0, TwistPoint b0,
            CurvePoint a1, TwistPoint b1,
            CurvePoint a2, TwistPoint b2,
            CurvePoint a3, TwistPoint b3) : bool {
        FQ12 acc = BN256.FQ12One;

        a0 = BN256.makeAffineCurvePoint(a0);
        a1 = BN256.makeAffineCurvePoint(a1);
        a2 = BN256.makeAffineCurvePoint(a2);
        a3 = BN256.makeAffineCurvePoint(a3);

        if (!BN256.isInfCurvePoint(a0) && !BN256.isInfTwistPoint(b0)) {
            acc = BN256.mulFQ12(acc, miller(b0, a0));
        }
        if (!BN256.isInfCurvePoint(a1) && !BN256.isInfTwistPoint(b1)) {
            acc = BN256.mulFQ12(acc, miller(b1, a1));
        }
        if (!BN256.isInfCurvePoint(a2) && !BN256.isInfTwistPoint(b2)) {
            acc = BN256.mulFQ12(acc, miller(b2, a2));
        }
        if (!BN256.isInfCurvePoint(a3) && !BN256.isInfTwistPoint(b3)) {
            acc = BN256.mulFQ12(acc, miller(b3, a3));
        }

        acc = finalExponentiation(acc);

        return acc == BN256.FQ12One;
    }

    static function pair(G1Point g1, G2Point g2) : FQ12 {
        return pairInternal(
                BN256.createCurvePoint(g1), 
                BN256.createTwistPoint(g2)
            );
    }

    // Check four pairs.
    // e(a0, b0) * ... * e(a3, b3) == 1
    static function pairCheckP4(
            G1Point a0, G2Point b0,
            G1Point a1, G2Point b1,
            G1Point a2, G2Point b2,
            G1Point a3, G2Point b3) : bool {
        return pairCheckP4Internal(
                BN256.createCurvePoint(a0), BN256.createTwistPoint(b0),
                BN256.createCurvePoint(a1), BN256.createTwistPoint(b1),
                BN256.createCurvePoint(a2), BN256.createTwistPoint(b2),
                BN256.createCurvePoint(a3), BN256.createTwistPoint(b3)
            );
    }
            

}
"#;

    [
        bn256_lib,
        pairing_lib,
    ]
    .join("\n")
}
