use crate::Scheme;
use serde::{de::DeserializeOwned, Serialize};
use zokrates_common::helpers::CurveParameter;
use zokrates_field::{Bn128Field, Bls12_381Field, Field};

pub trait ScryptCompatibleField: Field {}
impl ScryptCompatibleField for Bn128Field {}
impl ScryptCompatibleField for Bls12_381Field {}
pub trait ScryptCompatibleScheme<T: ScryptCompatibleField>: Scheme<T> {
    type Proof: From<Self::ProofPoints> + Serialize + DeserializeOwned + Clone;

    fn export_scrypt_verifier(vk: Self::VerificationKey, alpha_g1_beta_g2: String, curve_parameter: CurveParameter) -> String;
}


pub fn scrypt_pairing_lib_bn128() -> String {
    let bn256_lib = r#"
import { and, assert, SmartContract, SmartContractLib, method, lshift, prop, FixedArray } from 'scrypt-ts'

export type FQ = bigint

export type FQ2 = {
    x: FQ
    y: FQ
}

export type FQ6 = {
    x: FQ2
    y: FQ2
    z: FQ2
}

// FQ12 implements the field of size p¹² as a quadratic extension of FQ6
// where ω²=τ.
export type FQ12 = {
    x: FQ6
    y: FQ6
}

export type CurvePoint = {
    x: FQ
    y: FQ
    z: FQ
    t: FQ
}

export type TwistPoint = {
    x: FQ2
    y: FQ2
    z: FQ2
    t: FQ2
}

// These two are just to make it easier for users to interface with the code
// by not having them to deal with z and t coords.
//
export type G1Point = {
    x: FQ
    y: FQ
}

export type G2Point = {
    x: FQ2
    y: FQ2
}

export class BN256 extends SmartContractLib {
    // Curve bits:
    @prop()
    static readonly CURVE_BITS = 256n
    @prop()
    static readonly CURVE_BITS_P8 = 264n // +8 bits
    @prop()
    static readonly CURVE_BITS_P8_DIV12 = 88n

    // Key int size:
    @prop()
    static readonly S = 33n // 32 bytes plus sign byte

    // Upper bound of the eGCD mod inverse loop:
    @prop()
    static readonly UB = 368n

    // Generator of G1:
    @prop()
    static readonly G1: CurvePoint = {
        x: 1n,
        y: 2n,
        z: 1n,
        t: 1n,
    }

    // Generator of G2:
    @prop()
    static readonly G2: TwistPoint = {
        x: {
            x: 11559732032986387107991004021392285783925812861821192530917403151452391805634n,
            y: 10857046999023057135944570762232829481370756359578518086990519993285655852781n,
        },
        y: {
            x: 4082367875863433681332203403145435568316851327593401208105741076214120093531n,
            y: 8495653923123431417604973247489272438418190587263600148770280649306958101930n,
        },
        z: {
            x: 0n,
            y: 1n,
        },
        t: {
            x: 0n,
            y: 1n,
        },
    }

    @prop()
    static readonly FQ2Zero: FQ2 = {
        x: 0n,
        y: 0n,
    }

    @prop()
    static readonly FQ2One: FQ2 = {
        x: 0n,
        y: 1n,
    }

    @prop()
    static readonly FQ6Zero: FQ6 = {
        x: BN256.FQ2Zero,
        y: BN256.FQ2Zero,
        z: BN256.FQ2Zero,
    }

    @prop()
    static readonly FQ6One: FQ6 = {
        x: BN256.FQ2Zero,
        y: BN256.FQ2Zero,
        z: BN256.FQ2One,
    }

    @prop()
    static readonly FQ12Zero: FQ12 = {
        x: BN256.FQ6Zero,
        y: BN256.FQ6Zero,
    }

    @prop()
    static readonly FQ12One: FQ12 = {
        x: BN256.FQ6Zero,
        y: BN256.FQ6One,
    }

    // Curve field modulus:
    @prop()
    static readonly P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583n

    // xiToPMinus1Over6 is ξ^((p-1)/6) where ξ = i+9.
    @prop()
    static readonly xiToPMinus1Over6: FQ2 = {
        x: 16469823323077808223889137241176536799009286646108169935659301613961712198316n,
        y: 8376118865763821496583973867626364092589906065868298776909617916018768340080n,
    }

    // xiTo2PMinus2Over3 is ξ^((2p-2)/3) where ξ = i+9.
    @prop()
    static readonly xiTo2PMinus2Over3: FQ2 = {
        x: 19937756971775647987995932169929341994314640652964949448313374472400716661030n,
        y: 2581911344467009335267311115468803099551665605076196740867805258568234346338n,
    }

    // xiToPMinus1Over2 is ξ^((p-1)/2) where ξ = i+9.
    @prop()
    static readonly xiToPMinus1Over2: FQ2 = {
        x: 3505843767911556378687030309984248845540243509899259641013678093033130930403n,
        y: 2821565182194536844548159561693502659359617185244120367078079554186484126554n,
    }

    // xiToPMinus1Over3 is ξ^((p-1)/3) where ξ = i+9.
    @prop()
    static readonly xiToPMinus1Over3: FQ2 = {
        x: 10307601595873709700152284273816112264069230130616436755625194854815875713954n,
        y: 21575463638280843010398324269430826099269044274347216827212613867836435027261n,
    }

    // xiTo2PSquaredMinus2Over3 is ξ^((2p²-2)/3) where ξ = i+9 (a cubic root of unity, mod p).
    @prop()
    static readonly xiTo2PSquaredMinus2Over3: FQ =
        2203960485148121921418603742825762020974279258880205651966n

    // xiToPSquaredMinus1Over3 is ξ^((p²-1)/3) where ξ = i+9.
    @prop()
    static readonly xiToPSquaredMinus1Over3: FQ =
        21888242871839275220042445260109153167277707414472061641714758635765020556616n

    // xiToPSquaredMinus1Over6 is ξ^((1p²-1)/6) where ξ = i+9 (a cubic root of -1, mod p).
    @prop()
    static readonly xiToPSquaredMinus1Over6: FQ =
        21888242871839275220042445260109153167277707414472061641714758635765020556617n

    @method()
    static compareFQ2(a: FQ2, b: FQ2): boolean {
        return a.x == b.x && a.y == b.y
    }

    @method()
    static compareFQ6(a: FQ6, b: FQ6): boolean {
        return (
            a.x.x == b.x.x &&
            a.x.y == b.x.y &&
            a.y.x == b.y.x &&
            a.y.y == b.y.y &&
            a.z.x == b.z.x &&
            a.z.y == b.z.y
        )
    }

    @method()
    static compareFQ12(a: FQ12, b: FQ12): boolean {
        return (
            a.x.x.x == b.x.x.x &&
            a.x.x.y == b.x.x.y &&
            a.x.y.x == b.x.y.x &&
            a.x.y.y == b.x.y.y &&
            a.x.z.x == b.x.z.x &&
            a.x.z.y == b.x.z.y &&
            a.y.x.x == b.y.x.x &&
            a.y.x.y == b.y.x.y &&
            a.y.y.x == b.y.y.x &&
            a.y.y.y == b.y.y.y &&
            a.y.z.x == b.y.z.x &&
            a.y.z.y == b.y.z.y
        )
    }

    @method()
    static compareCurvePoints(a: CurvePoint, b: CurvePoint): boolean {
        return a.x == b.x && a.y == b.y && a.z == b.z && a.t == b.t
    }

    @method()
    static compareTwistPoints(a: TwistPoint, b: TwistPoint): boolean {
        return (
            a.x.x == b.x.x &&
            a.x.y == b.x.y &&
            a.y.x == b.y.x &&
            a.y.y == b.y.y &&
            a.z.x == b.z.x &&
            a.z.y == b.z.y &&
            a.t.x == b.t.x &&
            a.t.y == b.t.y
        )
    }

    @method()
    static modReduce(x: bigint, modulus: bigint): bigint {
        const res = x % modulus
        return res < 0 ? res + modulus : res
    }

    @method()
    static modFQ2(t0: FQ2): FQ2 {
        t0.x = BN256.modReduce(t0.x, BN256.P)
        t0.y = BN256.modReduce(t0.y, BN256.P)
        return t0
    }

    @method()
    static modFQ12(t0: FQ12): FQ12 {
        t0.x.x.x = BN256.modReduce(t0.x.x.x, BN256.P)
        t0.x.x.y = BN256.modReduce(t0.x.x.y, BN256.P)
        t0.x.y.x = BN256.modReduce(t0.x.y.x, BN256.P)
        t0.x.y.y = BN256.modReduce(t0.x.y.y, BN256.P)
        t0.x.z.x = BN256.modReduce(t0.x.z.x, BN256.P)
        t0.x.z.y = BN256.modReduce(t0.x.z.y, BN256.P)
        t0.y.x.x = BN256.modReduce(t0.y.x.x, BN256.P)
        t0.y.x.y = BN256.modReduce(t0.y.x.y, BN256.P)
        t0.y.y.x = BN256.modReduce(t0.y.y.x, BN256.P)
        t0.y.y.y = BN256.modReduce(t0.y.y.y, BN256.P)
        t0.y.z.x = BN256.modReduce(t0.y.z.x, BN256.P)
        t0.y.z.y = BN256.modReduce(t0.y.z.y, BN256.P)
        return t0
    }

    @method()
    static modCurvePoint(t0: CurvePoint): CurvePoint {
        t0.x = BN256.modReduce(t0.x, BN256.P)
        t0.y = BN256.modReduce(t0.y, BN256.P)
        t0.z = BN256.modReduce(t0.z, BN256.P)
        t0.t = BN256.modReduce(t0.t, BN256.P)
        return t0
    }

    @method()
    static modTwistPoint(t0: TwistPoint): TwistPoint {
        t0.x.x = BN256.modReduce(t0.x.x, BN256.P)
        t0.x.y = BN256.modReduce(t0.x.y, BN256.P)
        t0.y.x = BN256.modReduce(t0.y.x, BN256.P)
        t0.y.y = BN256.modReduce(t0.y.y, BN256.P)
        t0.z.x = BN256.modReduce(t0.z.x, BN256.P)
        t0.z.y = BN256.modReduce(t0.z.y, BN256.P)
        t0.t.x = BN256.modReduce(t0.t.x, BN256.P)
        t0.t.y = BN256.modReduce(t0.t.y, BN256.P)
        return t0
    }

    @method()
    static mulFQ2(a: FQ2, b: FQ2): FQ2 {
        const tx = a.x * b.y
        const t = b.x * a.y
        const tx_2 = tx + t

        const ty = a.y * b.y
        const t_2 = a.x * b.x
        const ty_2 = ty - t_2

        return {
            x: BN256.modReduce(tx_2, BN256.P),
            y: BN256.modReduce(ty_2, BN256.P),
        }
    }

    @method()
    static mulXiFQ2(a: FQ2): FQ2 {
        // (xi+y)(i+3) = (9x+y)i+(9y-x)
        const tx = lshift(a.x, 3n) + a.x + a.y
        const ty = lshift(a.y, 3n) + a.y - a.x

        return {
            x: BN256.modReduce(tx, BN256.P),
            y: BN256.modReduce(ty, BN256.P),
        }
    }

    @method()
    static mulScalarFQ2(a: FQ2, scalar: bigint): FQ2 {
        return {
            x: BN256.modReduce(a.x * scalar, BN256.P),
            y: BN256.modReduce(a.y * scalar, BN256.P),
        }
    }

    @method()
    static addFQ2(a: FQ2, b: FQ2): FQ2 {
        const res: FQ2 = {
            x: BN256.modReduce(a.x + b.x, BN256.P),
            y: BN256.modReduce(a.y + b.y, BN256.P),
        }
        return res
    }

    @method()
    static subFQ2(a: FQ2, b: FQ2): FQ2 {
        const res: FQ2 = {
            x: BN256.modReduce(a.x - b.x, BN256.P),
            y: BN256.modReduce(a.y - b.y, BN256.P),
        }
        return res
    }

    @method()
    static negFQ2(a: FQ2): FQ2 {
        const res: FQ2 = {
            x: BN256.modReduce(a.x * -1n, BN256.P),
            y: BN256.modReduce(a.y * -1n, BN256.P),
        }
        return res
    }

    @method()
    static conjugateFQ2(a: FQ2): FQ2 {
        const res: FQ2 = {
            x: BN256.modReduce(a.x * -1n, BN256.P),
            y: BN256.modReduce(a.y, BN256.P),
        }
        return res
    }

    @method()
    static doubleFQ2(a: FQ2): FQ2 {
        const res: FQ2 = {
            x: BN256.modReduce(a.x * 2n, BN256.P),
            y: BN256.modReduce(a.y * 2n, BN256.P),
        }
        return res
    }

    @method()
    static squareFQ2(a: FQ2): FQ2 {
        const tx = a.y - a.x
        const ty = a.x + a.y
        const ty_2 = ty * tx

        const tx_2 = a.x * a.y * 2n

        const res: FQ2 = {
            x: BN256.modReduce(tx_2, BN256.P),
            y: BN256.modReduce(ty_2, BN256.P),
        }
        return res
    }

    @method()
    static modInverseBranchlessP(x: bigint): bigint {
        // This will get substituted by optimized ASM code at transpilation stage.
        // The bellow code is ran while executing in a JS context.
        return BN256.modInverseEGCD(x, BN256.P)
    }

    @method()
    static modInverseEGCD(x: bigint, m: bigint): bigint {
        // This will get substituted by optimized ASM code at transpilation stage.
        x = BN256.modReduce(x, BN256.P)

        let t = 0n
        let newt = 1n
        let r = m
        let newr = x

        let quotient = 0n
        let tmp = 0n
        for (let i = 0; i < BN256.UB; i++) {
            if (newr != 0n) {
                quotient = r / newr

                tmp = newt
                newt = t - quotient * newt
                t = tmp

                tmp = newr
                newr = r - quotient * newr
                r = tmp
            }
        }

        if (t < 0) {
            t = t + m
        }

        return t
    }

    @method()
    static inverseFQ2(a: FQ2): FQ2 {
        const t2 = a.y * a.y
        const t1 = a.x * a.x + t2

        const inv = BN256.modInverseBranchlessP(t1)

        const axNeg = a.x * -1n

        const res: FQ2 = {
            x: BN256.modReduce(axNeg * inv, BN256.P),
            y: BN256.modReduce(a.y * inv, BN256.P),
        }
        return res
    }

    @method()
    static mulFQ6(a: FQ6, b: FQ6): FQ6 {
        // "Multiplication and Squaring on Pairing-Friendly Fields"
        // Section 4, Karatsuba method.
        // http://eprint.iacr.org/2006/471.pdf

        const v0 = BN256.mulFQ2(a.z, b.z)
        const v1 = BN256.mulFQ2(a.y, b.y)
        const v2 = BN256.mulFQ2(a.x, b.x)

        let t0 = BN256.addFQ2(a.x, a.y)
        let t1 = BN256.addFQ2(b.x, b.y)
        let tz = BN256.mulFQ2(t0, t1)

        tz = BN256.subFQ2(tz, v1)
        tz = BN256.subFQ2(tz, v2)
        tz = BN256.mulXiFQ2(tz)
        tz = BN256.addFQ2(tz, v0)

        t0 = BN256.addFQ2(a.y, a.z)
        t1 = BN256.addFQ2(b.y, b.z)

        let ty = BN256.mulFQ2(t0, t1)
        ty = BN256.subFQ2(ty, v0)
        ty = BN256.subFQ2(ty, v1)
        t0 = BN256.mulXiFQ2(v2)
        ty = BN256.addFQ2(ty, t0)

        t0 = BN256.addFQ2(a.x, a.z)
        t1 = BN256.addFQ2(b.x, b.z)
        let tx = BN256.mulFQ2(t0, t1)
        tx = BN256.subFQ2(tx, v0)
        tx = BN256.addFQ2(tx, v1)
        tx = BN256.subFQ2(tx, v2)

        const res: FQ6 = {
            x: tx,
            y: ty,
            z: tz,
        }
        return res
    }

    @method()
    static doubleFQ6(a: FQ6): FQ6 {
        const res: FQ6 = {
            x: BN256.doubleFQ2(a.x),
            y: BN256.doubleFQ2(a.y),
            z: BN256.doubleFQ2(a.z),
        }
        return res
    }

    @method()
    static mulScalarFQ6(a: FQ6, scalar: FQ2): FQ6 {
        const res: FQ6 = {
            x: BN256.mulFQ2(a.x, scalar),
            y: BN256.mulFQ2(a.y, scalar),
            z: BN256.mulFQ2(a.z, scalar),
        }
        return res
    }

    @method()
    static addFQ6(a: FQ6, b: FQ6): FQ6 {
        const res: FQ6 = {
            x: BN256.addFQ2(a.x, b.x),
            y: BN256.addFQ2(a.y, b.y),
            z: BN256.addFQ2(a.z, b.z),
        }
        return res
    }

    @method()
    static subFQ6(a: FQ6, b: FQ6): FQ6 {
        const res: FQ6 = {
            x: BN256.subFQ2(a.x, b.x),
            y: BN256.subFQ2(a.y, b.y),
            z: BN256.subFQ2(a.z, b.z),
        }
        return res
    }

    @method()
    static negFQ6(a: FQ6): FQ6 {
        const res: FQ6 = {
            x: BN256.negFQ2(a.x),
            y: BN256.negFQ2(a.y),
            z: BN256.negFQ2(a.z),
        }
        return res
    }

    @method()
    static squareFQ6(a: FQ6): FQ6 {
        const v0 = BN256.squareFQ2(a.z)
        const v1 = BN256.squareFQ2(a.y)
        const v2 = BN256.squareFQ2(a.x)

        let c0 = BN256.addFQ2(a.x, a.y)
        c0 = BN256.squareFQ2(c0)
        c0 = BN256.subFQ2(c0, v1)
        c0 = BN256.subFQ2(c0, v2)
        c0 = BN256.mulXiFQ2(c0)
        c0 = BN256.addFQ2(c0, v0)

        let c1 = BN256.addFQ2(a.y, a.z)
        c1 = BN256.squareFQ2(c1)
        c1 = BN256.subFQ2(c1, v0)
        c1 = BN256.subFQ2(c1, v1)
        const xiV2 = BN256.mulXiFQ2(v2)
        c1 = BN256.addFQ2(c1, xiV2)

        let c2 = BN256.addFQ2(a.x, a.z)
        c2 = BN256.squareFQ2(c2)
        c2 = BN256.subFQ2(c2, v0)
        c2 = BN256.addFQ2(c2, v1)
        c2 = BN256.subFQ2(c2, v2)

        const res: FQ6 = {
            x: c2,
            y: c1,
            z: c0,
        }
        return res
    }

    @method()
    static mulTauFQ6(a: FQ6): FQ6 {
        // MulTau computes τ·(aτ²+bτ+c) = bτ²+cτ+aξ
        const res: FQ6 = {
            x: a.y,
            y: a.z,
            z: BN256.mulXiFQ2(a.x),
        }
        return res
    }

    @method()
    static inverseFQ6(a: FQ6): FQ6 {
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

        let A = BN256.squareFQ2(a.z)
        let t1 = BN256.mulFQ2(a.x, a.y)
        t1 = BN256.mulXiFQ2(t1)
        A = BN256.subFQ2(A, t1)

        let B = BN256.squareFQ2(a.x)
        B = BN256.mulXiFQ2(B)
        t1 = BN256.mulFQ2(a.y, a.z)
        B = BN256.subFQ2(B, t1)

        let C = BN256.squareFQ2(a.y)
        t1 = BN256.mulFQ2(a.x, a.z)
        C = BN256.subFQ2(C, t1)

        let F = BN256.mulFQ2(C, a.y)
        F = BN256.mulXiFQ2(F)
        t1 = BN256.mulFQ2(A, a.z)
        F = BN256.addFQ2(F, t1)
        t1 = BN256.mulFQ2(B, a.x)
        t1 = BN256.mulXiFQ2(t1)
        F = BN256.addFQ2(F, t1)

        F = BN256.inverseFQ2(F)

        const res: FQ6 = {
            x: BN256.mulFQ2(C, F),
            y: BN256.mulFQ2(B, F),
            z: BN256.mulFQ2(A, F),
        }
        return res
    }

    @method()
    static mulScalarFQ12(a: FQ12, scalar: FQ6): FQ12 {
        const res: FQ12 = {
            x: BN256.mulFQ6(a.x, scalar),
            y: BN256.mulFQ6(a.y, scalar),
        }
        return res
    }

    @method()
    static inverseFQ12(a: FQ12): FQ12 {
        // See "Implementing cryptographic pairings", M. Scott, section 3.2.
        // ftp://136.206.11.249/pub/crypto/pairings.pdf

        const t1 = BN256.squareFQ6(a.x)
        const t2 = BN256.squareFQ6(a.y)
        const t1_2 = BN256.mulTauFQ6(t1)
        const t1_3 = BN256.subFQ6(t2, t1_2)
        const t2_2 = BN256.inverseFQ6(t1_3)

        const e: FQ12 = {
            x: BN256.negFQ6(a.x),
            y: a.y,
        }

        return BN256.mulScalarFQ12(e, t2_2)
    }

    @method()
    static mulFQ12(a: FQ12, b: FQ12): FQ12 {
        // This will get substituted by optimized ASM code at transpilation stage.
        const tx = BN256.mulFQ6(a.x, b.y)
        const t = BN256.mulFQ6(b.x, a.y)
        const tx2 = BN256.addFQ6(tx, t)

        const ty = BN256.mulFQ6(a.y, b.y)
        const t2 = BN256.mulFQ6(a.x, b.x)
        const t3 = BN256.mulTauFQ6(t2)

        const res: FQ12 = {
            x: tx2,
            y: BN256.addFQ6(ty, t3),
        }
        return res
    }

    @method()
    static frobeniusFQ6(a: FQ6): FQ6 {
        const res: FQ6 = {
            x: BN256.mulFQ2(BN256.conjugateFQ2(a.x), BN256.xiTo2PMinus2Over3),
            y: BN256.mulFQ2(BN256.conjugateFQ2(a.y), BN256.xiToPMinus1Over3),
            z: BN256.conjugateFQ2(a.z),
        }
        return res
    }

    @method()
    static frobeniusP2FQ6(a: FQ6): FQ6 {
        // FrobeniusP2 computes (xτ²+yτ+z)^(p²) = xτ^(2p²) + yτ^(p²) + z
        const res: FQ6 = {
            // τ^(2p²) = τ²τ^(2p²-2) = τ²ξ^((2p²-2)/3)
            x: BN256.mulScalarFQ2(a.x, BN256.xiTo2PSquaredMinus2Over3),
            // τ^(p²) = ττ^(p²-1) = τξ^((p²-1)/3)
            y: BN256.mulScalarFQ2(a.y, BN256.xiToPSquaredMinus1Over3),
            z: a.z,
        }
        return res
    }

    @method()
    static mulGFP(a: FQ6, b: bigint): FQ6 {
        return {
            x: BN256.mulScalarFQ2(a.x, b),
            y: BN256.mulScalarFQ2(a.y, b),
            z: BN256.mulScalarFQ2(a.z, b),
        }
    }

    @method()
    static conjugateFQ12(a: FQ12): FQ12 {
        const res: FQ12 = {
            x: BN256.negFQ6(a.x),
            y: a.y,
        }
        return res
    }

    @method()
    static frobeniusFQ12(a: FQ12): FQ12 {
        // Frobenius computes (xω+y)^p = x^p ω·ξ^((p-1)/6) + y^p
        return {
            x: BN256.mulScalarFQ6(
                BN256.frobeniusFQ6(a.x),
                BN256.xiToPMinus1Over6
            ),
            y: BN256.frobeniusFQ6(a.y),
        }
    }

    @method()
    static frobeniusP2FQ12(a: FQ12): FQ12 {
        // FrobeniusP2 computes (xω+y)^p² = x^p² ω·ξ^((p²-1)/6) + y^p²
        return {
            x: BN256.mulGFP(
                BN256.frobeniusP2FQ6(a.x),
                BN256.xiToPSquaredMinus1Over6
            ),
            y: BN256.frobeniusP2FQ6(a.y),
        }
    }

    @method()
    static squareFQ12(a: FQ12): FQ12 {
        // This will get substituted by optimized ASM code at transpilation stage.
        // Complex squaring algorithm
        const v0 = BN256.mulFQ6(a.x, a.y)

        const t = BN256.mulTauFQ6(a.x)
        const t2 = BN256.addFQ6(a.y, t)
        const ty = BN256.addFQ6(a.x, a.y)
        const ty2 = BN256.mulFQ6(ty, t2)
        const ty3 = BN256.subFQ6(ty2, v0)
        const t3 = BN256.mulTauFQ6(v0)

        const ty4 = BN256.subFQ6(ty3, t3)

        const res: FQ12 = {
            x: BN256.doubleFQ6(v0),
            y: ty4,
        }
        return res
    }

    @method()
    static expFQ12_u(a: FQ12): FQ12 {
        // u is the BN parameter that determines the prime.
        // u = 4965661367192848881;
        const sum = BN256.FQ12One

        // Unrolled loop. Reference impl.:
        // https://github.com/ethereum/go-ethereum/blob/bd6879ac518431174a490ba42f7e6e822dcb3ee1/crypto/bn256/google/gfp12.go#L138
        let sum0 = BN256.squareFQ12(sum)
        sum0 = BN256.modFQ12(sum0)
        const sum1 = BN256.mulFQ12(sum0, a)
        const sum2 = BN256.squareFQ12(sum1)
        const sum3 = BN256.squareFQ12(sum2)
        const sum4 = BN256.squareFQ12(sum3)
        const sum5 = BN256.squareFQ12(sum4)
        const sum6 = BN256.mulFQ12(sum5, a)
        const sum7 = BN256.squareFQ12(sum6)
        const sum8 = BN256.squareFQ12(sum7)
        const sum9 = BN256.squareFQ12(sum8)
        let sum10 = BN256.mulFQ12(sum9, a)
        sum10 = BN256.modFQ12(sum10)
        const sum11 = BN256.squareFQ12(sum10)
        const sum12 = BN256.mulFQ12(sum11, a)
        const sum13 = BN256.squareFQ12(sum12)
        const sum14 = BN256.mulFQ12(sum13, a)
        const sum15 = BN256.squareFQ12(sum14)
        const sum16 = BN256.squareFQ12(sum15)
        const sum17 = BN256.mulFQ12(sum16, a)
        const sum18 = BN256.squareFQ12(sum17)
        const sum19 = BN256.squareFQ12(sum18)
        let sum20 = BN256.squareFQ12(sum19)
        sum20 = BN256.modFQ12(sum20)
        const sum21 = BN256.mulFQ12(sum20, a)
        const sum22 = BN256.squareFQ12(sum21)
        const sum23 = BN256.mulFQ12(sum22, a)
        const sum24 = BN256.squareFQ12(sum23)
        const sum25 = BN256.squareFQ12(sum24)
        const sum26 = BN256.squareFQ12(sum25)
        const sum27 = BN256.mulFQ12(sum26, a)
        const sum28 = BN256.squareFQ12(sum27)
        const sum29 = BN256.squareFQ12(sum28)
        let sum30 = BN256.squareFQ12(sum29)
        sum30 = BN256.modFQ12(sum30)
        const sum31 = BN256.mulFQ12(sum30, a)
        const sum32 = BN256.squareFQ12(sum31)
        const sum33 = BN256.squareFQ12(sum32)
        const sum34 = BN256.mulFQ12(sum33, a)
        const sum35 = BN256.squareFQ12(sum34)
        const sum36 = BN256.squareFQ12(sum35)
        const sum37 = BN256.mulFQ12(sum36, a)
        const sum38 = BN256.squareFQ12(sum37)
        const sum39 = BN256.mulFQ12(sum38, a)
        let sum40 = BN256.squareFQ12(sum39)
        sum40 = BN256.modFQ12(sum40)
        const sum41 = BN256.squareFQ12(sum40)
        const sum42 = BN256.mulFQ12(sum41, a)
        const sum43 = BN256.squareFQ12(sum42)
        const sum44 = BN256.squareFQ12(sum43)
        const sum45 = BN256.squareFQ12(sum44)
        const sum46 = BN256.squareFQ12(sum45)
        const sum47 = BN256.mulFQ12(sum46, a)
        const sum48 = BN256.squareFQ12(sum47)
        const sum49 = BN256.squareFQ12(sum48)
        let sum50 = BN256.squareFQ12(sum49)
        sum50 = BN256.modFQ12(sum50)
        const sum51 = BN256.mulFQ12(sum50, a)
        const sum52 = BN256.squareFQ12(sum51)
        const sum53 = BN256.squareFQ12(sum52)
        const sum54 = BN256.mulFQ12(sum53, a)
        const sum55 = BN256.squareFQ12(sum54)
        const sum56 = BN256.squareFQ12(sum55)
        const sum57 = BN256.squareFQ12(sum56)
        const sum58 = BN256.mulFQ12(sum57, a)
        const sum59 = BN256.squareFQ12(sum58)
        let sum60 = BN256.mulFQ12(sum59, a)
        sum60 = BN256.modFQ12(sum60)
        const sum61 = BN256.squareFQ12(sum60)
        const sum62 = BN256.squareFQ12(sum61)
        const sum63 = BN256.mulFQ12(sum62, a)
        const sum64 = BN256.squareFQ12(sum63)
        const sum65 = BN256.squareFQ12(sum64)
        const sum66 = BN256.squareFQ12(sum65)
        const sum67 = BN256.mulFQ12(sum66, a)
        const sum68 = BN256.squareFQ12(sum67)
        const sum69 = BN256.squareFQ12(sum68)
        let sum70 = BN256.squareFQ12(sum69)
        sum70 = BN256.modFQ12(sum70)
        const sum71 = BN256.squareFQ12(sum70)
        const sum72 = BN256.squareFQ12(sum71)
        const sum73 = BN256.mulFQ12(sum72, a)
        const sum74 = BN256.squareFQ12(sum73)
        const sum75 = BN256.squareFQ12(sum74)
        const sum76 = BN256.squareFQ12(sum75)
        const sum77 = BN256.mulFQ12(sum76, a)
        const sum78 = BN256.squareFQ12(sum77)
        const sum79 = BN256.mulFQ12(sum78, a)
        let sum80 = BN256.squareFQ12(sum79)
        sum80 = BN256.modFQ12(sum80)
        const sum81 = BN256.mulFQ12(sum80, a)
        const sum82 = BN256.squareFQ12(sum81)
        const sum83 = BN256.mulFQ12(sum82, a)
        const sum84 = BN256.squareFQ12(sum83)
        const sum85 = BN256.mulFQ12(sum84, a)
        const sum86 = BN256.squareFQ12(sum85)
        const sum87 = BN256.squareFQ12(sum86)
        const sum88 = BN256.squareFQ12(sum87)
        const sum89 = BN256.squareFQ12(sum88)
        let sum90 = BN256.mulFQ12(sum89, a)
        sum90 = BN256.modFQ12(sum90)

        return sum90
    }

    @method()
    static expFQ12(a: FQ12, power: bigint): FQ12 {
        let sum = BN256.FQ12One
        let t = BN256.FQ12One

        let firstOne = false

        for (let i = 0; i < BN256.CURVE_BITS_P8; i++) {
            if (firstOne) {
                t = BN256.modFQ12(BN256.squareFQ12(sum))
            }

            const shifted = lshift(
                1n,
                BigInt(Number(BN256.CURVE_BITS_P8) - 1 - i)
            )

            if (and(power, shifted) != 0n) {
                firstOne = true
                sum = BN256.mulFQ12(t, a)
            } else {
                sum = t
            }
        }

        return sum
    }

    @method()
    static doubleG1Point(a: G1Point): G1Point {
        const res = BN256.doubleCurvePoint(BN256.createCurvePoint(a))
        return BN256.getG1Point(res)
    }

    @method()
    static doubleCurvePoint(a: CurvePoint): CurvePoint {
        // This will get substituted by optimized ASM code at transpilation stage.
        // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
        const res: CurvePoint = {
            x: 0n,
            y: 0n,
            z: 0n,
            t: 0n,
        }

        const A = BN256.modReduce(a.x * a.x, BN256.P)
        const B = BN256.modReduce(a.y * a.y, BN256.P)
        const C = BN256.modReduce(B * B, BN256.P)

        let t = a.x + B
        let t2 = BN256.modReduce(t * t, BN256.P)
        t = t2 - A
        t2 = t - C

        const d = t2 * 2n
        t = A * 2n
        const e = t + A
        const f = BN256.modReduce(e * e, BN256.P)

        t = d * 2n
        res.x = f - t

        t = C * 2n
        t2 = t * 2n
        t = t2 * 2n
        res.y = d - res.x
        t2 = BN256.modReduce(e * res.y, BN256.P)
        res.y = t2 - t

        const prod = a.y * a.z
        res.z = BN256.modReduce(prod, BN256.P) * 2n

        return res
    }

    @method()
    static addG1Points(a: G1Point, b: G1Point): G1Point {
        const res = BN256.addCurvePoints(
            BN256.createCurvePoint(a),
            BN256.createCurvePoint(b)
        )
        return BN256.getG1Point(res)
    }

    @method()
    static addCurvePoints(a: CurvePoint, b: CurvePoint): CurvePoint {
        return BN256._addCurvePoints(BN256.P, a, b)
    }

    @method()
    static _addCurvePoints(
        P: bigint,
        a: CurvePoint,
        b: CurvePoint
    ): CurvePoint {
        // This will get substituted by optimized ASM code at transpilation stage.
        // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3
        let res: CurvePoint = {
            x: 0n,
            y: 0n,
            z: 0n,
            t: 0n,
        }

        if (a.z == 0n) {
            res = b
        } else if (b.z == 0n) {
            res = a
        } else {
            // Normalize the points by replacing a = [x1:y1:z1] and b = [x2:y2:z2]
            // by [u1:s1:z1·z2] and [u2:s2:z1·z2]
            // where u1 = x1·z2², s1 = y1·z2³ and u1 = x2·z1², s2 = y2·z1³

            const z12 = BN256.modReduce(a.z * a.z, P)
            const z22 = BN256.modReduce(b.z * b.z, P)

            const u1 = BN256.modReduce(a.x * z22, P)
            const u2 = BN256.modReduce(b.x * z12, P)

            let t = BN256.modReduce(b.z * z22, P)
            const s1 = BN256.modReduce(a.y * t, P)

            t = BN256.modReduce(a.z * z12, P)
            const s2 = BN256.modReduce(b.y * t, P)

            // Compute x = (2h)²(s²-u1-u2)
            // where s = (s2-s1)/(u2-u1) is the slope of the line through
            // (u1,s1) and (u2,s2). The extra factor 2h = 2(u2-u1) comes from the value of z below.
            // This is also:
            // 4(s2-s1)² - 4h²(u1+u2) = 4(s2-s1)² - 4h³ - 4h²(2u1)
            //                        = r² - j - 2v
            // with the notations below.

            const h = u2 - u1
            const xEqual = h == 0n

            t = h * 2n
            // i = 4h²
            const i = BN256.modReduce(t * t, P)
            // j = 4h³
            const j = BN256.modReduce(h * i, P)

            t = s2 - s1
            const yEqual = t == 0n

            if (xEqual && yEqual) {
                res = BN256.doubleCurvePoint(a)
            } else {
                const r = t + t
                const v = BN256.modReduce(u1 * i, P)

                // t4 = 4(s2-s1)²
                let t4 = BN256.modReduce(r * r, P)
                let t6 = t4 - j
                t = v * 2n

                res.x = t6 - t

                // Set y = -(2h)³(s1 + s*(x/4h²-u1))
                // This is also
                // y = - 2·s1·j - (s2-s1)(2x - 2i·u1) = r(v-x) - 2·s1·j
                t = v - res.x
                t4 = BN256.modReduce(s1 * j, P)
                t6 = t4 * 2n
                t4 = BN256.modReduce(r * t, P)
                res.y = t4 - t6

                // Set z = 2(u2-u1)·z1·z2 = 2h·z1·z2
                t = a.z + b.z
                t4 = BN256.modReduce(t * t, P)
                t = t4 - z12
                t4 = t - z22
                res.z = BN256.modReduce(t4 * h, P)
            }
        }

        return res
    }

    @method()
    static mulG1Point(a: G1Point, m: bigint): G1Point {
        const res = BN256.mulCurvePoint(BN256.createCurvePoint(a), m)
        return BN256.getG1Point(res)
    }

    @method()
    static mulCurvePoint(a: CurvePoint, m: bigint): CurvePoint {
        let res: CurvePoint = {
            x: 0n,
            y: 1n,
            z: 0n,
            t: 0n,
        }

        if (m != 0n) {
            // Double and add method.
            // Lowest bit to highest.
            let t: CurvePoint = {
                x: 0n,
                y: 0n,
                z: 0n,
                t: 0n,
            }
            let sum: CurvePoint = {
                x: 0n,
                y: 0n,
                z: 0n,
                t: 0n,
            }

            let firstOne = false

            for (let k = 0; k < BN256.CURVE_BITS_P8_DIV12; k++) {
                sum = BN256.modCurvePoint(sum)
                for (let j = 0; j < 3; j++) {
                    if (firstOne) {
                        t = BN256.doubleCurvePoint(sum)
                    }
                    const shifted = lshift(
                        1n,
                        BigInt(Number(BN256.CURVE_BITS_P8) - 1 - (3 * k + j))
                    )
                    if (and(m, shifted) != 0n) {
                        firstOne = true
                        sum = BN256.addCurvePoints(t, a)
                    } else {
                        sum = t
                    }
                }
            }
            res = sum
        }

        return res
    }

    @method()
    static makeAffineCurvePoint(a: CurvePoint): CurvePoint {
        // MakeAffine converts a to affine form. If c is ∞, then it sets
        // a to 0 : 1 : 0.

        let res = a
        if (BN256.modReduce(a.z, BN256.P) != 1n) {
            if (a.z == 0n) {
                res = {
                    x: 0n,
                    y: 1n,
                    z: 0n,
                    t: 0n,
                }
            } else {
                const zInv = BN256.modInverseBranchlessP(a.z)
                const t = BN256.modReduce(a.y * zInv, BN256.P)
                const zInv2 = BN256.modReduce(zInv * zInv, BN256.P)
                const ay = BN256.modReduce(t * zInv2, BN256.P)
                const ax = BN256.modReduce(a.x * zInv2, BN256.P)

                res = {
                    x: ax,
                    y: ay,
                    z: 1n,
                    t: 1n,
                }
            }
        }

        return res
    }

    @method()
    static negCurvePoint(a: CurvePoint): CurvePoint {
        const res: CurvePoint = {
            x: a.x,
            y: -a.y,
            z: a.z,
            t: 0n,
        }
        return res
    }

    @method()
    static isInfCurvePoint(a: CurvePoint): boolean {
        return a.z == 0n
    }

    @method()
    static createCurvePoint(ccp: G1Point): CurvePoint {
        let res: CurvePoint = {
            x: ccp.x,
            y: ccp.y,
            z: 1n,
            t: 1n,
        }
        if (ccp.x == 0n && ccp.y == 0n) {
            res = {
                x: 0n,
                y: 1n,
                z: 0n,
                t: 0n,
            }
        }
        return res
    }

    @method()
    static getG1Point(cp: CurvePoint): G1Point {
        const acp = BN256.makeAffineCurvePoint(cp)
        let res: G1Point = {
            x: acp.x,
            y: acp.y,
        }
        if (acp.x == 0n && acp.y == 1n && acp.z == 0n && acp.t == 0n) {
            res = {
                x: 0n,
                y: 0n,
            }
        }
        return res
    }

    @method()
    static doubleG2Point(a: G2Point): G2Point {
        const res = BN256.doubleTwistPoint(BN256.createTwistPoint(a))

        return BN256.getG2Point(res)
    }

    @method()
    static doubleTwistPoint(a: TwistPoint): TwistPoint {
        // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3

        const res: TwistPoint = {
            x: BN256.FQ2Zero,
            y: BN256.FQ2Zero,
            z: BN256.FQ2Zero,
            t: BN256.FQ2Zero,
        }

        const A = BN256.squareFQ2(a.x)
        const B = BN256.squareFQ2(a.y)
        const C = BN256.squareFQ2(B)

        let t = BN256.addFQ2(a.x, B)
        let t2 = BN256.squareFQ2(t)
        t = BN256.subFQ2(t2, A)
        t2 = BN256.subFQ2(t, C)

        const d = BN256.mulScalarFQ2(t2, 2n)
        t = BN256.mulScalarFQ2(A, 2n)
        const e = BN256.addFQ2(t, A)
        const f = BN256.squareFQ2(e)

        t = BN256.mulScalarFQ2(d, 2n)
        res.x = BN256.subFQ2(f, t)

        t = BN256.mulScalarFQ2(C, 2n)
        t2 = BN256.mulScalarFQ2(t, 2n)
        t = BN256.mulScalarFQ2(t2, 2n)
        res.y = BN256.subFQ2(d, res.x)
        t2 = BN256.mulFQ2(e, res.y)
        res.y = BN256.subFQ2(t2, t)

        res.z = BN256.mulScalarFQ2(BN256.mulFQ2(a.y, a.z), 2n)

        return res
    }

    @method()
    static addG2Points(a: G2Point, b: G2Point): G2Point {
        const res = BN256.addTwistPoints(
            BN256.createTwistPoint(a),
            BN256.createTwistPoint(b)
        )

        return BN256.getG2Point(res)
    }

    @method()
    static addTwistPoints(a: TwistPoint, b: TwistPoint): TwistPoint {
        let res: TwistPoint = {
            x: BN256.FQ2Zero,
            y: BN256.FQ2Zero,
            z: BN256.FQ2Zero,
            t: a.t,
        }

        if (a.z == BN256.FQ2Zero) {
            res = b
        } else if (b.z == BN256.FQ2Zero) {
            res = a
        } else {
            // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3

            // Normalize the points by replacing a = [x1:y1:z1] and b = [x2:y2:z2]
            // by [u1:s1:z1·z2] and [u2:s2:z1·z2]
            // where u1 = x1·z2², s1 = y1·z2³ and u1 = x2·z1², s2 = y2·z1³

            const z12 = BN256.squareFQ2(a.z)
            const z22 = BN256.squareFQ2(b.z)

            const u1 = BN256.mulFQ2(a.x, z22)
            const u2 = BN256.mulFQ2(b.x, z12)

            let t = BN256.mulFQ2(b.z, z22)
            const s1 = BN256.mulFQ2(a.y, t)

            t = BN256.mulFQ2(a.z, z12)
            const s2 = BN256.mulFQ2(b.y, t)

            // Compute x = (2h)²(s²-u1-u2)
            // where s = (s2-s1)/(u2-u1) is the slope of the line through
            // (u1,s1) and (u2,s2). The extra factor 2h = 2(u2-u1) comes from the value of z below.
            // This is also:
            // 4(s2-s1)² - 4h²(u1+u2) = 4(s2-s1)² - 4h³ - 4h²(2u1)
            //                        = r² - j - 2v
            // with the notations below.

            const h = BN256.subFQ2(u2, u1)
            const xEqual = h == BN256.FQ2Zero

            t = BN256.mulScalarFQ2(h, 2n)
            // i = 4h²
            const i = BN256.squareFQ2(t)
            // j = 4h³
            const j = BN256.mulFQ2(h, i)

            t = BN256.subFQ2(s2, s1)
            const yEqual = t == BN256.FQ2Zero
            if (xEqual && yEqual) {
                res = BN256.doubleTwistPoint(a)
            } else {
                const r = BN256.mulScalarFQ2(t, 2n)
                const v = BN256.mulFQ2(u1, i)

                // t4 = 4(s2-s1)²
                let t4 = BN256.squareFQ2(r)
                let t6 = BN256.subFQ2(t4, j)
                t = BN256.mulScalarFQ2(v, 2n)

                res.x = BN256.subFQ2(t6, t)

                // Set y = -(2h)³(s1 + s*(x/4h²-u1))
                // This is also
                // y = - 2·s1·j - (s2-s1)(2x - 2i·u1) = r(v-x) - 2·s1·j
                t = BN256.subFQ2(v, res.x)
                t4 = BN256.mulFQ2(s1, j)
                t6 = BN256.mulScalarFQ2(t4, 2n)
                t4 = BN256.mulFQ2(r, t)
                res.y = BN256.subFQ2(t4, t6)

                // Set z = 2(u2-u1)·z1·z2 = 2h·z1·z2
                t = BN256.addFQ2(a.z, b.z)
                t4 = BN256.squareFQ2(t)
                t = BN256.subFQ2(t4, z12)
                t4 = BN256.subFQ2(t, z22)
                res.z = BN256.mulFQ2(t4, h)
            }
        }

        return res
    }

    @method()
    static makeAffineTwistPoint(a: TwistPoint): TwistPoint {
        let res = a
        if (a.z.x != 0n || a.z.y != 1n) {
            if (a.z == BN256.FQ2Zero) {
                res = {
                    x: BN256.FQ2Zero,
                    y: BN256.FQ2One,
                    z: BN256.FQ2Zero,
                    t: BN256.FQ2Zero,
                }
            } else {
                const zInv = BN256.inverseFQ2(a.z)
                let t = BN256.mulFQ2(a.y, zInv)
                const zInv2 = BN256.squareFQ2(zInv)
                res.y = BN256.mulFQ2(t, zInv2)
                t = BN256.mulFQ2(a.x, zInv2)
                res.x = t

                const zTmp: FQ2 = { x: 0n, y: 1n }
                res.z = zTmp
                res.t = zTmp
            }
        }

        return res
    }

    @method()
    static negTwistPoint(a: TwistPoint): TwistPoint {
        const res: TwistPoint = {
            x: a.x,
            y: BN256.subFQ2(BN256.FQ2Zero, a.y),
            z: a.z,
            t: BN256.FQ2Zero,
        }
        return res
    }

    @method()
    static isInfTwistPoint(a: TwistPoint): boolean {
        return a.z.x == BN256.FQ2Zero.x && a.z.y == BN256.FQ2Zero.y
    }

    @method()
    static createTwistPoint(ctp: G2Point): TwistPoint {
        // Output x and y coords from ZoKrates need to be swaped to work correctly.
        const x: FQ2 = {
            x: ctp.x.y,
            y: ctp.x.x,
        }
        const y: FQ2 = {
            x: ctp.y.y,
            y: ctp.y.x,
        }

        let res: TwistPoint = {
            x: x,
            y: y,
            z: BN256.FQ2One,
            t: BN256.FQ2One,
        }

        if (ctp.x == BN256.FQ2Zero && ctp.y == BN256.FQ2Zero) {
            res = {
                x: BN256.FQ2Zero,
                y: BN256.FQ2One,
                z: BN256.FQ2Zero,
                t: BN256.FQ2Zero,
            }
        }
        return res
    }

    @method()
    static getG2Point(tp: TwistPoint): G2Point {
        const atp = BN256.makeAffineTwistPoint(tp)
        let res: G2Point = {
            x: atp.x,
            y: atp.y,
        }

        if (
            atp.x == BN256.FQ2Zero &&
            atp.y == BN256.FQ2One &&
            atp.z == BN256.FQ2Zero &&
            atp.t == BN256.FQ2Zero
        ) {
            res = {
                x: BN256.FQ2Zero,
                y: BN256.FQ2Zero,
            }
        }
        return res
    }
}
"#;



let pairing_lib = r#"

export type LineFuncRes = {
    a: FQ2
    b: FQ2
    c: FQ2
    rOut: TwistPoint
}

export class BN256Pairing extends SmartContractLib {
    @method()
    static compareLineFuncRes(a: LineFuncRes, b: LineFuncRes): boolean {
        return (
            a.a.x == b.a.x &&
            a.a.y == b.a.y &&
            a.b.x == b.b.x &&
            a.b.y == b.b.y &&
            a.c.x == b.c.x &&
            a.c.y == b.c.y &&
            a.rOut.x.x == b.rOut.x.x &&
            a.rOut.x.y == b.rOut.x.y &&
            a.rOut.y.x == b.rOut.y.x &&
            a.rOut.y.y == b.rOut.y.y &&
            a.rOut.z.x == b.rOut.z.x &&
            a.rOut.z.y == b.rOut.z.y &&
            a.rOut.t.x == b.rOut.t.x &&
            a.rOut.t.y == b.rOut.t.y
        )
    }

    @method()
    static modLineFuncRes(l: LineFuncRes): LineFuncRes {
        l.a = BN256.modFQ2(l.a)
        l.b = BN256.modFQ2(l.b)
        l.c = BN256.modFQ2(l.c)
        l.rOut.x = BN256.modFQ2(l.rOut.x)
        l.rOut.y = BN256.modFQ2(l.rOut.y)
        l.rOut.z = BN256.modFQ2(l.rOut.z)
        l.rOut.t = BN256.modFQ2(l.rOut.t)
        return l
    }

    @method()
    static lineFuncAdd(
        r: TwistPoint,
        p: TwistPoint,
        q: CurvePoint,
        r2: FQ2
    ): LineFuncRes {
        // This will get substituted by optimized ASM code at transpilation stage.

        // See the mixed addition algorithm from "Faster Computation of the
        // Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf

        const B = BN256.mulFQ2(p.x, r.t)
        let D = BN256.addFQ2(p.y, r.z)
        D = BN256.squareFQ2(D)
        D = BN256.subFQ2(D, r2)
        D = BN256.subFQ2(D, r.t)
        D = BN256.mulFQ2(D, r.t)

        const H = BN256.subFQ2(B, r.x)
        const I = BN256.squareFQ2(H)

        let E = BN256.addFQ2(I, I)
        E = BN256.addFQ2(E, E)

        const J = BN256.mulFQ2(H, E)

        let L1 = BN256.subFQ2(D, r.y)
        L1 = BN256.subFQ2(L1, r.y)

        const V = BN256.mulFQ2(r.x, E)

        let rOutX = BN256.squareFQ2(L1)
        rOutX = BN256.subFQ2(rOutX, J)
        rOutX = BN256.subFQ2(rOutX, V)
        rOutX = BN256.subFQ2(rOutX, V)

        let rOutZ = BN256.addFQ2(r.z, H)
        rOutZ = BN256.squareFQ2(rOutZ)
        rOutZ = BN256.subFQ2(rOutZ, r.t)
        rOutZ = BN256.subFQ2(rOutZ, I)

        let t = BN256.subFQ2(V, rOutX)
        t = BN256.mulFQ2(t, L1)
        let t2 = BN256.mulFQ2(r.y, J)
        t2 = BN256.addFQ2(t2, t2)
        const rOutY = BN256.subFQ2(t, t2)

        const rOutT = BN256.squareFQ2(rOutZ)

        t = BN256.addFQ2(p.y, rOutZ)
        t = BN256.squareFQ2(t)
        t = BN256.subFQ2(t, r2)
        t = BN256.subFQ2(t, rOutT)

        t2 = BN256.mulFQ2(L1, p.x)
        t2 = BN256.addFQ2(t2, t2)
        const a = BN256.subFQ2(t2, t)

        let c = BN256.mulScalarFQ2(rOutZ, q.y)
        c = BN256.addFQ2(c, c)

        let b = BN256.subFQ2(BN256.FQ2Zero, L1)
        b = BN256.mulScalarFQ2(b, q.x)
        b = BN256.addFQ2(b, b)

        const rOut: TwistPoint = {
            x: rOutX,
            y: rOutY,
            z: rOutZ,
            t: rOutT,
        }

        return {
            a: a,
            b: b,
            c: c,
            rOut: rOut,
        }
    }

    @method()
    static lineFuncDouble(r: TwistPoint, q: CurvePoint): LineFuncRes {
        // See the doubling algorithm for a=0 from "Faster Computation of the
        // Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf

        const A = BN256.squareFQ2(r.x)
        const B = BN256.squareFQ2(r.y)
        const C = BN256.squareFQ2(B)

        let D = BN256.addFQ2(r.x, B)
        D = BN256.squareFQ2(D)
        D = BN256.subFQ2(D, A)
        D = BN256.subFQ2(D, C)
        D = BN256.addFQ2(D, D)

        let E = BN256.addFQ2(A, A)
        E = BN256.addFQ2(E, A)

        const G = BN256.squareFQ2(E)

        let rOutX = BN256.subFQ2(G, D)
        rOutX = BN256.subFQ2(rOutX, D)

        let rOutZ = BN256.addFQ2(r.y, r.z)
        rOutZ = BN256.squareFQ2(rOutZ)
        rOutZ = BN256.subFQ2(rOutZ, B)
        rOutZ = BN256.subFQ2(rOutZ, r.t)

        let rOutY = BN256.subFQ2(D, rOutX)
        rOutY = BN256.mulFQ2(rOutY, E)
        let t = BN256.addFQ2(C, C)
        t = BN256.addFQ2(t, t)
        t = BN256.addFQ2(t, t)
        rOutY = BN256.subFQ2(rOutY, t)

        const rOutT = BN256.squareFQ2(rOutZ)

        t = BN256.mulFQ2(E, r.t)
        t = BN256.addFQ2(t, t)
        let b = BN256.subFQ2(BN256.FQ2Zero, t)
        b = BN256.mulScalarFQ2(b, q.x)

        let a = BN256.addFQ2(r.x, E)
        a = BN256.squareFQ2(a)
        a = BN256.subFQ2(a, A)
        a = BN256.subFQ2(a, G)
        t = BN256.addFQ2(B, B)
        t = BN256.addFQ2(t, t)
        a = BN256.subFQ2(a, t)

        let c = BN256.mulFQ2(rOutZ, r.t)
        c = BN256.addFQ2(c, c)
        c = BN256.mulScalarFQ2(c, q.y)

        const rOut: TwistPoint = {
            x: rOutX,
            y: rOutY,
            z: rOutZ,
            t: rOutT,
        }

        return {
            a: a,
            b: b,
            c: c,
            rOut: rOut,
        }
    }

    @method()
    static mulLine(ret: FQ12, a: FQ2, b: FQ2, c: FQ2): FQ12 {
        let a2: FQ6 = {
            x: BN256.FQ2Zero,
            y: a,
            z: b,
        }
        a2 = BN256.mulFQ6(a2, ret.x)
        const t3 = BN256.mulScalarFQ6(ret.y, c)

        const t = BN256.addFQ2(b, c)
        const t2: FQ6 = {
            x: BN256.FQ2Zero,
            y: a,
            z: t,
        }

        let resX = BN256.addFQ6(ret.x, ret.y)
        let resY = t3

        resX = BN256.mulFQ6(resX, t2)
        resX = BN256.subFQ6(resX, a2)
        resX = BN256.subFQ6(resX, resY)
        a2 = BN256.mulTauFQ6(a2)
        resY = BN256.addFQ6(resY, a2)

        return {
            x: resX,
            y: resY,
        }
    }

    @method()
    static miller(q: TwistPoint, p: CurvePoint): FQ12 {
        let ret = BN256.FQ12One

        const aAffine = BN256.makeAffineTwistPoint(q)
        const bAffine = BN256.makeAffineCurvePoint(p)

        const minusA = BN256.negTwistPoint(aAffine)

        let r = aAffine

        let r2 = BN256.squareFQ2(aAffine.y)

        // sixuPlus2NAF is 6u+2 in non-adjacent form.
        // Unrolled loop to get rid of in-loop branching. Reference impl.:
        // https://github.com/ethereum/go-ethereum/blob/bd6879ac518431174a490ba42f7e6e822dcb3ee1/crypto/bn256/google/optate.go#L213
        // var sixuPlus2NAF = {}int8{0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0,
        //                           0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0, 1, 1,
        //                           1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1,
        //                           1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, 1, 1}

        //---- 1
        let lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- -1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, minusA, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- -1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, minusA, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- -1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, minusA, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- -1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, minusA, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- -1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, minusA, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- -1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, minusA, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- -1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, minusA, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- -1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, minusA, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 1
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        lfr = BN256Pairing.lineFuncAdd(r, aAffine, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut
        //---- 0
        r = BN256.modTwistPoint(r)
        ret = BN256.modFQ12(ret)
        lfr = BN256Pairing.lineFuncDouble(r, bAffine)
        ret = BN256.squareFQ12(ret)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

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

        let q1x = BN256.conjugateFQ2(aAffine.x)
        q1x = BN256.mulFQ2(q1x, BN256.xiToPMinus1Over3)
        let q1y = BN256.conjugateFQ2(aAffine.y)
        q1y = BN256.mulFQ2(q1y, BN256.xiToPMinus1Over2)

        const q1: TwistPoint = {
            x: q1x,
            y: q1y,
            z: { x: 0n, y: 1n },
            t: { x: 0n, y: 1n },
        }

        // For Q2 we are applying the p² Frobenius. The two conjugations cancel
        // out and we are left only with the factors from the isomorphism. In
        // the case of x, we end up with a pure number which is why
        // xiToPSquaredMinus1Over3 is ∈ GF(p). With y we get a factor of -1. We
        // ignore this to end up with -Q2.

        const minusQ2x = BN256.mulScalarFQ2(
            aAffine.x,
            BN256.xiToPSquaredMinus1Over3
        )
        const minusQ2: TwistPoint = {
            x: minusQ2x,
            y: aAffine.y,
            z: { x: 0n, y: 1n },
            t: { x: 0n, y: 1n },
        }

        r2 = BN256.squareFQ2(q1.y)
        lfr = BN256Pairing.lineFuncAdd(r, q1, bAffine, r2)
        ret = BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c)
        r = lfr.rOut

        r2 = BN256.squareFQ2(minusQ2.y)
        lfr = BN256Pairing.lineFuncAdd(r, minusQ2, bAffine, r2)
        return BN256.modFQ12(BN256Pairing.mulLine(ret, lfr.a, lfr.b, lfr.c))
    }

    @method()
    static finalExponentiation(a: FQ12): FQ12 {
        let t1: FQ12 = {
            x: BN256.negFQ6(a.x),
            y: a.y,
        }

        const inv = BN256.inverseFQ12(a)
        t1 = BN256.mulFQ12(t1, inv)

        const t2 = BN256.frobeniusP2FQ12(t1)
        t1 = BN256.mulFQ12(t1, t2)

        let fp = BN256.frobeniusFQ12(t1)
        let fp2 = BN256.frobeniusP2FQ12(t1)
        let fp3 = BN256.frobeniusFQ12(fp2)
        fp = BN256.modFQ12(fp)
        fp2 = BN256.modFQ12(fp2)
        fp3 = BN256.modFQ12(fp3)

        const fu = BN256.expFQ12_u(t1)
        const fu2 = BN256.expFQ12_u(fu)
        const fu3 = BN256.expFQ12_u(fu2)

        let y3 = BN256.frobeniusFQ12(fu)
        const fu2p = BN256.frobeniusFQ12(fu2)
        const fu3p = BN256.frobeniusFQ12(fu3)
        const y2 = BN256.frobeniusP2FQ12(fu2)

        let y0 = BN256.mulFQ12(fp, fp2)
        y0 = BN256.mulFQ12(y0, fp3)

        const y1 = BN256.conjugateFQ12(t1)
        const y5 = BN256.conjugateFQ12(fu2)
        y3 = BN256.conjugateFQ12(y3)
        let y4 = BN256.mulFQ12(fu, fu2p)
        y4 = BN256.conjugateFQ12(y4)

        let y6 = BN256.mulFQ12(fu3, fu3p)
        y6 = BN256.conjugateFQ12(y6)

        let t0 = BN256.squareFQ12(y6)
        t0 = BN256.modFQ12(t0)
        t0 = BN256.mulFQ12(t0, y4)
        t0 = BN256.mulFQ12(t0, y5)
        t1 = BN256.mulFQ12(y3, y5)
        t1 = BN256.mulFQ12(t1, t0)
        t0 = BN256.mulFQ12(t0, y2)
        t1 = BN256.squareFQ12(t1)
        t1 = BN256.mulFQ12(t1, t0)
        t1 = BN256.squareFQ12(t1)
        t0 = BN256.mulFQ12(t1, y1)
        t1 = BN256.mulFQ12(t1, y0)
        t0 = BN256.squareFQ12(t0)
        t0 = BN256.mulFQ12(t0, t1)
        t0 = BN256.modFQ12(t0)

        return t0
    }

    @method()
    static _pair(g1: CurvePoint, g2: TwistPoint): FQ12 {
        const e = BN256Pairing.miller(g2, g1)
        let ret = BN256Pairing.finalExponentiation(e)

        if (BN256.isInfTwistPoint(g2) || BN256.isInfCurvePoint(g1)) {
            ret = BN256.FQ12One
        }

        return ret
    }

    @method()
    static pair(g1: G1Point, g2: G2Point): FQ12 {
        return BN256Pairing._pair(
            BN256.createCurvePoint(g1),
            BN256.createTwistPoint(g2)
        )
    }

    @method()
    static _pairCheckP4Precalc(
        a0: CurvePoint,
        b0: TwistPoint,
        millerBetaAlpha: FQ12,
        a2: CurvePoint,
        b2: TwistPoint,
        a3: CurvePoint,
        b3: TwistPoint
    ): boolean {
        a0 = BN256.makeAffineCurvePoint(a0)
        a2 = BN256.makeAffineCurvePoint(a2)
        a3 = BN256.makeAffineCurvePoint(a3)

        let acc = millerBetaAlpha

        if (!BN256.isInfCurvePoint(a0) && !BN256.isInfTwistPoint(b0)) {
            acc = BN256.mulFQ12(acc, BN256Pairing.miller(b0, a0))
        }
        acc = BN256.modFQ12(acc)
        if (!BN256.isInfCurvePoint(a2) && !BN256.isInfTwistPoint(b2)) {
            acc = BN256.mulFQ12(acc, BN256Pairing.miller(b2, a2))
        }
        acc = BN256.modFQ12(acc)
        if (!BN256.isInfCurvePoint(a3) && !BN256.isInfTwistPoint(b3)) {
            acc = BN256.mulFQ12(acc, BN256Pairing.miller(b3, a3))
        }
        acc = BN256.modFQ12(acc)

        acc = BN256Pairing.finalExponentiation(acc)

        return BN256.compareFQ12(acc, BN256.FQ12One)
    }

    @method()
    static pairCheckP4Precalc(
        a0: G1Point,
        b0: G2Point,
        millerBetaAlpha: FQ12,
        a2: G1Point,
        b2: G2Point,
        a3: G1Point,
        b3: G2Point
    ): boolean {
        return BN256Pairing._pairCheckP4Precalc(
            BN256.createCurvePoint(a0),
            BN256.createTwistPoint(b0),
            millerBetaAlpha,
            BN256.createCurvePoint(a2),
            BN256.createTwistPoint(b2),
            BN256.createCurvePoint(a3),
            BN256.createTwistPoint(b3)
        )
    }

    @method()
    static _pairCheckP2Precalc(
        a0: CurvePoint,
        b0: TwistPoint,
        a1: CurvePoint,
        b1: TwistPoint
    ): boolean {
        let acc = BN256.FQ12One

        a0 = BN256.makeAffineCurvePoint(a0)
        a1 = BN256.makeAffineCurvePoint(a1)

        if (!BN256.isInfCurvePoint(a0) && !BN256.isInfTwistPoint(b0)) {
            acc = BN256.mulFQ12(acc, BN256Pairing.miller(b0, a0))
        }

        if (!BN256.isInfCurvePoint(a1) && !BN256.isInfTwistPoint(b1)) {
            acc = BN256.mulFQ12(acc, BN256Pairing.miller(b1, a1))
        }

        acc = BN256Pairing.finalExponentiation(acc)

        return acc == BN256.FQ12One
    }

    @method()
    static pairCheckP2Precalc(
        a0: G1Point,
        b0: G2Point,
        a1: G1Point,
        b1: G2Point
    ): boolean {
        return BN256Pairing._pairCheckP2Precalc(
            BN256.createCurvePoint(a0),
            BN256.createTwistPoint(b0),
            BN256.createCurvePoint(a1),
            BN256.createTwistPoint(b1)
        )
    }
}
 
"#;

    [
        bn256_lib,
        pairing_lib,
    ]
    .join("\n")
}

pub fn scrypt_pairing_lib_bls12_381() -> String {
    let bls12_381_lib = r#"
type fe   = int;
type fe2  = fe[2];
type fe6  = fe2[3];
type fe12 = fe6[2];

type fp2 = fe2[2];
// PointG1 is type for point in G1.
// PointG1 is both used for Affine and Jacobian point representation.
// If z is equal to one the point is considered as in affine form.
type PointG1 = fe[3];
// PointG2 is type for point in G2.
// PointG2 is both used for Affine and Jacobian point representation.
// If z is equal to one the point is considered as in affine form.
type PointG2 = fe2[3];

// G1 is struct for G1 group.
type G1 = fe[9];
// G2 is struct for G2 group.
type G2 = fe2[9];
// GT is type for target multiplicative group GT.
type GT = fe12;


library BLS12381 {
    //----------------Field Constants
    // Base field modulus
    static fe P = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    // r mod p
    static const fe r1 = 0x15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd;

    //Montgomery form
    static const int R1sft384 = 0x01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
    static const int Minv_neg = 0x00ceb06106feaafc9468b316fee268cf5819ecca0e8eb2db4c16ef2ef0c8e30b48286adb92d9d113e889f3fffcfffcfffd;

    //----------------
    static const int S = 32;
    static const bytes mask = reverseBytes(num2bin(1, S), S);
    static const bytes zero = reverseBytes(num2bin(0, S), S);

    static const fe2 Fe2Zero = [0, 0];
    static const fe6 Fe6Zero = repeat(Fe2Zero, 3);
    static const fe12 Fe12Zero = [Fe6Zero, Fe6Zero];
    static const G1 G1Zero = repeat(0, 9);
    static const G2 G2Zero = repeat(Fe2Zero, 9);
    static const PointG1 PtG1Zero = [0, 0, 0];
    //static const PointG2 PtG2Zero = [0, 0, 0];
    static const fe2 [6]Fe2_6Zero = repeat(Fe2Zero, 6);

    //----------------Frobenious Coeffs
    static const fe2 [6]frobeniusCoeffs61 = [
        [r1, 0],
        [0, 0x18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071],
        [0x051ba4ab241b61603636b76660701c6ec26a2ff874fd029b16a8ca3ac61577f7f3b8ddab7ece5a2a30f1361b798a64e8, 0],
        [0, r1],
        [0x18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071, 0],
        [0, 0x051ba4ab241b61603636b76660701c6ec26a2ff874fd029b16a8ca3ac61577f7f3b8ddab7ece5a2a30f1361b798a64e8]
    ];

    static const fe2 [6]frobeniusCoeffs62 = [
        [r1, 0],
        [0x14e56d3f1564853a14e4f04fe2db9068a20d1b8c7e88102450880866309b7e2c2af322533285a5d5890dc9e4867545c3, 0],
        [0x18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071, 0],
        [0x040ab3263eff0206ef148d1ea0f4c069eca8f3318332bb7a07e83a49a2e99d6932b7fff2ed47fffd43f5fffffffcaaae, 0],
        [0x051ba4ab241b61603636b76660701c6ec26a2ff874fd029b16a8ca3ac61577f7f3b8ddab7ece5a2a30f1361b798a64e8, 0],
        [0x0110f184e51c5f5947222a47bf7b5c04d5c13cc6f1ca47210ec08ff1232bda8ec100ddb891865a2cecfb361b798dba3a, 0]
    ];

    static const fe2 [12]frobeniusCoeffs12 = [
        [r1, 0],
        [0x08f2220fb0fb66eb1ce393ea5daace4da35baecab2dc29ee97e83cccd117228fc6695f92b50a831307089552b319d465,
         0x110eefda88847faf2e3813cbe5a0de89c11b9cba40a8e8d0cf4895d42599d3945842a06bfc497cecb2f66aad4ce5d646],
        [0x0110f184e51c5f5947222a47bf7b5c04d5c13cc6f1ca47210ec08ff1232bda8ec100ddb891865a2cecfb361b798dba3a, 0],
        [0x0bd592fc7d825ec81d794e4fac7cf0b992ad2afd19103e18382844c88b6237324294213d86c181833e2f585da55c9ad1,
         0x0e2b7eedbbfd87d22da2596696cebc1dd1ca2087da74d4a72f088dd86b4ebef1dc17dec12a927e7c7bcfa7a25aa30fda],
        [0x051ba4ab241b61603636b76660701c6ec26a2ff874fd029b16a8ca3ac61577f7f3b8ddab7ece5a2a30f1361b798a64e8, 0],
        [0x02e370eccc86f7dd0095ba654ed2226bef517c3266341429a04007fbba4b14a27c2ac1aad1b6fe703726c30af242c66c,
         0x171da0fd6cf8eebd4a85ed50f4798a6b7525cf528d50fe95c6f0caa53c65e181a2813e53df9d018f82d83cf50dbce43f],
        [0x040ab3263eff0206ef148d1ea0f4c069eca8f3318332bb7a07e83a49a2e99d6932b7fff2ed47fffd43f5fffffffcaaae, 0],
        [0x110eefda88847faf2e3813cbe5a0de89c11b9cba40a8e8d0cf4895d42599d3945842a06bfc497cecb2f66aad4ce5d646,
         0x08f2220fb0fb66eb1ce393ea5daace4da35baecab2dc29ee97e83cccd117228fc6695f92b50a831307089552b319d465],
        [0x18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071, 0],
        [0x0e2b7eedbbfd87d22da2596696cebc1dd1ca2087da74d4a72f088dd86b4ebef1dc17dec12a927e7c7bcfa7a25aa30fda,
         0x0bd592fc7d825ec81d794e4fac7cf0b992ad2afd19103e18382844c88b6237324294213d86c181833e2f585da55c9ad1],
        [0x14e56d3f1564853a14e4f04fe2db9068a20d1b8c7e88102450880866309b7e2c2af322533285a5d5890dc9e4867545c3, 0],
        [0x171da0fd6cf8eebd4a85ed50f4798a6b7525cf528d50fe95c6f0caa53c65e181a2813e53df9d018f82d83cf50dbce43f,
         0x02e370eccc86f7dd0095ba654ed2226bef517c3266341429a04007fbba4b14a27c2ac1aad1b6fe703726c30af242c66c]
    ];

    //----------------
    // static const int UB = 768; 
    static const int UB = 548; 
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

    static function mod(fe a, fe modulus) : fe {
        const fe res = a % modulus;
        return res >= 0 ? res : modulus + res;
    }

    //--------------------- 

    static function oneFe2() : fe2 {
        return [r1, 0];
    }

    static function zeroFe2() : fe2 {
        return Fe2Zero;
    }

    static function isOneFe2(fe2 e2) : bool {
	    return e2[0] == r1 && e2[1] == 0;
    }

    static function isZeroFe2(fe2 e2) : bool {
	    return e2[0] == 0 && e2[1] == 0;
    }

    static function equalFe2(fe2 a, fe2 b) : bool {
        return a[0] == b[0] && a[1] == b[1];
    }

    static function isOneFe6(fe6 e) : bool {
	    return isOneFe2(e[0]) && isZeroFe2(e[1]) && isZeroFe2(e[2]);
    }

    static function isZeroFe6(fe6 e) : bool {
	    return isZeroFe2(e[0]) && isZeroFe2(e[1]) && isZeroFe2(e[2]);
    }

    static function zeroFe6() : fe6 {
        return [zeroFe2(), zeroFe2(), zeroFe2()];
    }

    static function oneFe6() : fe6 {
        return [oneFe2(), zeroFe2(), zeroFe2()];
    }

    static function oneFe12() : fe12 {
        return [oneFe6(), zeroFe6()];
    }

    static function isOneFe12(fe12 e) : bool {
	    return isOneFe6(e[0]) && isZeroFe6(e[1]);
    }


    //--------------------- 
    static function toMont(fe a) : fe {
        fe res = a << 384;
        res = res % P;
        return res;
    }

    static function fromMont(fe a) : fe {
        fe U = mod(a * Minv_neg, R1sft384);
        fe T = a + U * P >> 384;

        return mod(T, P);
    }

    static function mulFe(fe a, fe b) : fe {
        return fromMont(mod(a * b, P));
    }

    static function squareFe(fe a) : fe {
        return fromMont(mod(a * a, P));
    }

    static function inverse(fe e) : fe {
        // fe inv = 0;
        // if(e != 0) {
        //     fe u = P;
        //     fe v = e;
        //     fe s = 1;
        //     fe r = 0;
        //     int k = 0;
        //     int z = 0;
        //     bool found = false;

        // 	// Phase 1
        //     loop(768) : i {
        //         if(found == false) {
        //             if(v == 0) {
        //                 found = true;
        //             } else {
        //                 if(u % 2 == 0) {
        //                     u = u >> 1;
        //                     s = s << 1;
        //                 } else if(v % 2 == 0) {
        //                     v = v >> 1;
        //                     r = r << 1;
        //                     z = z + (r >> 383);
        //                 } else if(u > v) {
        //                     u = u - v;
        //                     u = u >> 1;
        //                     r = r + s;
        //                     s = s << 1;
        //                 } else {
        //                     v = v - u;
        //                     v = v >> 1;
        //                     s = s + r;
        //                     r = r << 1;
        //                     z = z + (r >> 383);
        //                 }
        //                 k = k + 1;
        //             }
        //         }
        //     }

        //     if(found == false) {
        //         inv = 0;
        //     } else {
        //         if(k < 381 || k > 381 + 384) {
        //             inv = 0;
        //         } else {
        //             if(r >= P || z > 0) {
        //                 r = r - P;
        //             }
        //             u = P;
        //             u = u - r;

        //             loop(768) : i {
        //                 if(i >= k) {
        //                     u = u << 1;
        //                 }
        //             }
        //             inv = mod(u, P);
        //         }
        //     }
        // }
        // return inv;

        return toMont(toMont(modInverseEGCD(e, P)));
    }

    //--------------------- 
    static function addFe2(fe2 a, fe2 b) : fe2 {
        return [mod(a[0] + b[0], P), mod(a[1] + b[1], P)];
    }

    static function doubleFe2(fe2 a) : fe2 {
        return [mod(a[0] + a[0], P), mod(a[1] + a[1], P)
        ];
    }

    static function subFe2(fe2 a, fe2 b) : fe2 {
        return [mod(a[0] - b[0], P), mod(a[1] - b[1], P)];
    }

    static function negFe2(fe2 a) : fe2 {
        return [mod(a[0] * -1, P), mod(a[1] * -1, P)];
    }

    static function mulFe2(fe2 a, fe2 b) : fe2 {
        fe [4]t = [0, 0, 0, 0];
        fe2 c = Fe2Zero;

        t[0] = mod(a[0] * b[1], P);
        t[1] = mod(b[0] * a[1], P);
        c[1] = fromMont(mod(t[0] + t[1], P));

        t[2] = mod(a[1] * b[1], P);
        t[3] = mod(a[0] * b[0], P);
        c[0] = fromMont(mod(t[3] - t[2], P));

        return c;
    }

    static function squareFe2(fe2 a) : fe2 {
        fe [4]t = [0, 0, 0, 0];
        fe2 c = Fe2Zero;

        t[0] = mod(a[0] + a[1], P);
        t[1] = mod(a[0] - a[1], P);
        t[2] = mod(a[0] + a[0], P);
        c[0] = fromMont(mod(t[0] * t[1], P));
        c[1] = fromMont(mod(t[2] * a[1], P));

        return c;
    }

   static function mulByNonResidueFe2(fe2 a) : fe2 {
        fe2 c = Fe2Zero;
        fe2 t = Fe2Zero;

        t[0] = mod(a[0] - a[1], P);
        c[1] = mod(a[0] + a[1], P);
        c[0] = t[0];
        return c;
    }

    static function inverseFe2(fe2 a) : fe2 {
        fe2 c = Fe2Zero;
        fe2 t = Fe2Zero;
        t[0] = mod(a[0] * a[0], P);
        t[1] = mod(a[1] * a[1], P);
        t[0] = mod(t[0] + t[1], P);
        t[0] = inverse(t[0]);
        c[0] = mod(a[0] * t[0], P);
        t[0] = mod(t[0] * a[1], P);
        c[1] = mod(t[0] *-1, P);
        return  c;
    }

    //--------------------- 
    static function addFe6(fe6 a, fe6 b) : fe6 {
        return [addFe2(a[0], b[0]), addFe2(a[1], b[1]), addFe2(a[2], b[2])];
    }

    static function doubleFe6(fe6 a) : fe6 {	
        return [doubleFe2(a[0]), doubleFe2(a[1]), doubleFe2(a[2])];	
    }	

    static function subFe6(fe6 a, fe6 b) : fe6 {	
        return [subFe2(a[0], b[0]),	subFe2(a[1], b[1]), subFe2(a[2], b[2])];	
    }	

    static function negFe6(fe6 a) : fe6 {
        return [negFe2(a[0]), negFe2(a[1]), negFe2(a[2])];
    }

    static function mulFe6(fe6 a, fe6 b) : fe6 {
        fe6 c = Fe6Zero;
        fe2 [6]t = Fe2_6Zero;

        t[0] = mulFe2(a[0], b[0]);
        t[1] = mulFe2(a[1], b[1]);
        t[2] = mulFe2(a[2], b[2]);
        t[3] = addFe2(a[1], a[2]);
        t[4] = addFe2(b[1], b[2]);        
        t[3] = mulFe2(t[3], t[4]);
        t[4] = addFe2(t[1], t[2]);  
        t[3] = subFe2(t[3], t[4]);
        t[3] = mulByNonResidueFe2(t[3]);
        t[5] = addFe2(t[0], t[3]);

        t[3] = addFe2(a[0], a[1]);
        t[4] = addFe2(b[0], b[1]);
        t[3] = mulFe2(t[3], t[4]);
        t[4] = addFe2(t[0], t[1]);
        t[3] = subFe2(t[3], t[4]);
        t[4] = mulByNonResidueFe2(t[2]);
        c[1] = addFe2(t[3], t[4]);

        t[3] = addFe2(a[0], a[2]);
        t[4] = addFe2(b[0], b[2]);
        t[3] = mulFe2(t[3], t[4]);
        t[4] = addFe2(t[0], t[2]);
        t[3] = subFe2(t[3], t[4]);
        c[2] = addFe2(t[1], t[3]);

        c[0] = t[5];

        return c;
    }

    static function mulByNonResidueFe6(fe6 a) : fe6 {
        fe6 c = Fe6Zero;

        c[0] = mulByNonResidueFe2(a[2]);
        c[2] = a[1];
        c[1] = a[0];

        return c;
    }

    static function mulFe12(fe12 a, fe12 b) : fe12 {
        fe12 c = Fe12Zero;
        fe6 [4]t = repeat(Fe6Zero, 4);

        t[1] = mulFe6(a[0], b[0]);
        t[2] = mulFe6(a[1], b[1]);
        t[0] = addFe6(t[1], t[2]);
        t[2] = mulByNonResidueFe6(t[2]);
        t[3] = addFe6(t[1], t[2]);
        t[1] = addFe6(a[0], a[1]);
        t[2] = addFe6(b[0], b[1]);
        t[1] = mulFe6(t[1], t[2]);

        c[0] = t[3];
        c[1] = subFe6(t[1], t[0]);

        return c;
    }

    static function conjugateFe12(fe12 a) : fe12 {
        fe12 c = Fe12Zero;

        c[0] = a[0];
        c[1] = negFe6(a[1]);
        return c;
    }


    //--------------------- for millerLoop()
    static function mulByFqFe2(fe2 a, fe b) : fe2 {
        fe2 c = Fe2Zero;
        c[0] = fromMont(mod(a[0] * b, P));
        c[1] = fromMont(mod(a[1] * b, P));
        return  c;
    }

   static function mulByBFe2(fe2 a) : fe2 {
        fe2 c = Fe2Zero;
        fe2 t = Fe2Zero;

        t[0] = mod(a[0] + a[0], P);
        t[1] = mod(a[1] + a[1], P);
        t[0] = mod(t[0] + t[0], P);
        t[1] = mod(t[1] + t[1], P);
        c[0] = mod(t[0] - t[1], P);
        c[1] = mod(t[0] + t[1], P);
        return c;
   }

    static function mulBy01Fe6(fe6 a, fe2 b0, fe2 b1) : fe6 {
        fe6 c = Fe6Zero;
        fe2 [6]t = Fe2_6Zero;

        t[0] = mulFe2(a[0], b0);
        t[1] = mulFe2(a[1], b1);
        t[2] = addFe2(a[1], a[2]);
        t[2] = mulFe2(t[2], b1);
        t[2] = subFe2(t[2], t[1]);
        t[2] = mulByNonResidueFe2(t[2]);
        t[3] = addFe2(a[0], a[2]);
        t[3] = mulFe2(t[3], b0);
        t[3] = subFe2(t[3], t[0]);
        c[2] = addFe2(t[3], t[1]);
        t[4] = addFe2(b0, b1);
        t[3] = addFe2(a[0], a[1]);
        t[4] = mulFe2(t[4], t[3]);
        t[4] = subFe2(t[4], t[0]);
        c[1] = subFe2(t[4], t[1]);
        c[0] = addFe2(t[2], t[0]);
        return c;
    }

    static function mulBy1Fe6(fe6 a, fe2 b1) : fe6 {
        fe6 c = Fe6Zero;
        fe2 [6]t = Fe2_6Zero;

        t[0] = mulFe2(a[2], b1);
        c[2] = mulFe2(a[1], b1);
        c[1] = mulFe2(a[0], b1);
        c[0] = mulByNonResidueFe2(t[0]);
        return c;
    }

    static function squareFe12(fe12 a) : fe12 {
        fe12 c = Fe12Zero;
        fe6 [4]t = repeat(Fe6Zero, 4);

        t[0] = addFe6(a[0], a[1]);
        t[2] = mulFe6(a[0], a[1]);
        t[1] = mulByNonResidueFe6(a[1]);
        t[1] = addFe6(t[1], a[0]);
        t[3] = mulByNonResidueFe6(t[2]);
        t[0] = mulFe6(t[0], t[1]);
        t[0] = subFe6(t[0], t[2]);
        c[0] = subFe6(t[0], t[3]);
        c[1] = doubleFe6(t[2]);

        return c;
    }

    static function mulBy014AssignFe12(fe12 a, fe2 c0, fe2 c1, fe2 c4) : fe12 {
        fe6 [5]t = repeat(Fe6Zero, 5);
        fe2 t2 = Fe2Zero;

        t[0] = mulBy01Fe6(a[0], c0, c1);
        t[1] = mulBy1Fe6(a[1], c4);
        t2 = addFe2(c1, c4);
        t[2] = addFe6(a[1], a[0]);
        t[2] = mulBy01Fe6(t[2], c0, t2);
        t[2] = subFe6(t[2], t[0]);
        a[1] = subFe6(t[2], t[1]);
        t[1] = mulByNonResidueFe6(t[1]);
        a[0] = addFe6(t[1], t[0]);
        return a;
    }

    //--------------------- for finalExp()

    static function fp4Square(fe2 c0, fe2 c1, fe2 a0, fe2 a1) : fe2[2] {
        fe2 [9]t = G2Zero;

        t[0] = squareFe2(a0);
        t[1] = squareFe2(a1);
        t[2] = mulByNonResidueFe2(t[1]);
        c0 = addFe2(t[2], t[0]);
        t[2] = addFe2(a0, a1);
        t[2] = squareFe2(t[2]);
        t[2] = subFe2(t[2], t[0]);
        c1 = subFe2(t[2], t[1]);

        return [c0, c1];
    }

    static function mulByBaseFieldFe6(fe6 a, fe2 b) : fe6 {
        fe6 c = Fe6Zero;

        c[0] = mulFe2(a[0], b);
        c[1] = mulFe2(a[1], b);
        c[2] = mulFe2(a[2], b);

        return c;
    }

    static function squareFe6(fe6 a) : fe6 {
        fe6 c = Fe6Zero;
        fe2 [6]t = Fe2_6Zero;

        t[0] = squareFe2(a[0]);
        t[1] = doubleFe2(mulFe2(a[0], a[1]));
        t[2] = squareFe2(addFe2(subFe2(a[0], a[1]), a[2]));
        t[3] = doubleFe2(mulFe2(a[1], a[2]));
        t[4] = squareFe2(a[2]);
        t[5] = mulByNonResidueFe2(t[3]);

        c[0] = addFe2(t[0], t[5]);
        t[5] = mulByNonResidueFe2(t[4]);
        c[1] = addFe2(t[1], t[5]);
        t[1] = addFe2(t[1], t[2]);
        t[1] = addFe2(t[1], t[3]);
        t[0] = addFe2(t[0], t[4]);
        c[2] = subFe2(t[1], t[0]);

        return c;
    }

    static function inverseFe6(fe6 a) : fe6 {
        fe6 c = Fe6Zero;
        fe2 [6]t = Fe2_6Zero;

        t[0] = squareFe2(a[0]);
        t[1] = mulByNonResidueFe2(mulFe2(a[1], a[2]));
        t[0] = subFe2(t[0], t[1]);
        t[1] = squareFe2(a[1]);
        t[2] = mulFe2(a[0], a[2]);
        t[1] = subFe2(t[1], t[2]);
        t[2] = mulByNonResidueFe2(squareFe2(a[2]));
        t[3] = mulFe2(a[0], a[1]);
        t[2] = subFe2(t[2], t[3]);
        t[3] = mulFe2(a[2], t[2]);
        t[4] = mulFe2(a[1], t[1]);
        t[3] = mulByNonResidueFe2(addFe2(t[3], t[4]));
        t[4] = mulFe2(a[0], t[0]);
        t[3] = inverseFe2(addFe2(t[3], t[4]));
        c[0] = mulFe2(t[0], t[3]);
        c[1] = mulFe2(t[2], t[3]);
        c[2] = mulFe2(t[1], t[3]);

        return c;
    }

    static function inverseFe12(fe12 a) : fe12 {
        fe12 c = Fe12Zero;
        fe6 [2]t = repeat(Fe6Zero, 2);

        t[0] = squareFe6(a[0]);
        t[1] = mulByNonResidueFe6(squareFe6(a[1]));
        t[1] = subFe6(t[0], t[1]);
        t[0] = inverseFe6(t[1]);

        c[0] = mulFe6(a[0], t[0]);
        t[0] = mulFe6(t[0], a[1]);
        c[1] = negFe6(t[0]);

        return c;
    }

    static function cyclotomicSquare(fe12 a) : fe12 {
        fe12 c = Fe12Zero;
        fe2 [9]t = G2Zero;
        fe2 [2] d = repeat(Fe2Zero, 2);

        d = fp4Square(t[3], t[4], a[0][0], a[1][1]);
        t[3] = d[0];
        t[4] = d[1];
        t[2] = subFe2(t[3], a[0][0]);
        t[2] = doubleFe2(t[2]);
        c[0][0] = addFe2(t[2], t[3]);        
        t[2] = addFe2(t[4], a[1][1]);
        t[2] = doubleFe2(t[2]);
        c[1][1] = addFe2(t[2], t[4]); 
        d = fp4Square(t[3], t[4], a[1][0], a[0][2]);
        t[3] = d[0];
        t[4] = d[1];
        d = fp4Square(t[5], t[6], a[0][1], a[1][2]);
        t[5] = d[0];
        t[6] = d[1];
        t[2] = subFe2(t[3], a[0][1]);
        t[2] = doubleFe2(t[2]);
        c[0][1] = addFe2(t[2], t[3]);        
        t[2] = addFe2(t[4], a[1][2]);
        t[2] = doubleFe2(t[2]);
        c[1][2] = addFe2(t[2], t[4]);   
        t[3] = mulByNonResidueFe2(t[6]);
        t[2] = addFe2(t[3], a[1][0]);
        t[2] = doubleFe2(t[2]);
        c[1][0] = addFe2(t[2], t[3]);   
        t[2] = subFe2(t[5], a[0][2]);
        t[2] = doubleFe2(t[2]);
        c[0][2] = addFe2(t[2], t[5]);   
        return c;
    }

    //1101 0010 0000 0001 0000 0000 0000 0000 0000 0000 0000 0001 0000 0000 0000 0000
    static function cyclotomicExp2(fe12 a) : fe12 {
        fe12 z = oneFe12();

        // z = cyclotomicSquare(z);
        // z = mulFe12(z, a);
        z = cyclotomicSquare(a);
        z = mulFe12(z, a);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = mulFe12(z, a);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = mulFe12(z, a);
        z = cyclotomicSquare(z);

        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = mulFe12(z, a);

        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);

        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);

        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);

        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = mulFe12(z, a);

        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);

        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);
        z = cyclotomicSquare(z);

        return z;
    }

    static function frobeniusMapFe2(fe2 a, fe power) : fe2 {
        fe2 c = Fe2Zero;

        c[0] = a[0];
        if(power % 2 == 1) {
            c[1] = mod(a[1] * -1, P);
        } else {
            c[1] = a[1];
        }
        
        return c;
    }

    static function frobeniusMapFe6(fe6 a, fe power) : fe6 {
        fe6 c = Fe6Zero;
        int tt = 0;

        c[0] = frobeniusMapFe2(a[0], power);
        c[1] = frobeniusMapFe2(a[1], power);
        c[2] = frobeniusMapFe2(a[2], power);

        int w = power % 6;
        if(w == 3) {
            tt = mod(c[1][1] * -1, P);
            c[1][1] = c[1][0];
            c[1][0] = tt;
            c[2] = negFe2(c[2]);
        } else if(w != 0) {
            c[1] = mulFe2(c[1], frobeniusCoeffs61[w]);
            c[2] = mulFe2(c[2], frobeniusCoeffs62[w]);
        }

        return c;
    }

    static function frobeniusMapFe12(fe12 a, fe power) : fe12 {
        fe12 c = Fe12Zero;

        c[0] = frobeniusMapFe6(a[0], power);
        c[1] = frobeniusMapFe6(a[1], power);

        if(power == 6) {
            c[1] = negFe6(c[1]);
        } else if(power != 0) {
            c[1] = mulByBaseFieldFe6(c[1], frobeniusCoeffs12[power]);
        }

        return c;
    }

    //--------------------- 
    static function IsZeroG1(PointG1 c) : bool {
        return c[2] == 0;
    }

    static function IsAffineG1(PointG1 p) : bool {
        return p[2] == BLS12381.r1;
    }

    static function AffineG1(PointG1 p) : PointG1 {
        PointG1 res = p;

        if(IsZeroG1(p) == false) {
            if(IsAffineG1(p) == false) {
                G1 t = G1Zero;
                t[0] = inverse(p[2]);
                t[1] = squareFe(t[0]);
                p[0] = mulFe(p[0], t[1]);
                t[0] = mulFe(t[0], t[1]);
                p[1] = mulFe(p[1], t[0]);
                p[2] = r1;

                res = p;
            }
        }
        return res;
    }

    // http://www.hyperelliptic.org/EFD/gp/auto-shortw-jacobian-0.html#addition-add-2007-bl
    static function AddG1(PointG1 p1, PointG1 p2) : PointG1 {
        PointG1 res = PtG1Zero;
        G1 t = G1Zero;

    	if(IsZeroG1(p1)) {
		    res = p2;
        } else if(IsZeroG1(p2)) {
		    res = p1;
        } else {
            t[7] = squareFe(p1[2]);
            t[1] = mulFe(p2[0], t[7]);
            t[2] = mulFe(p1[2], t[7]);
            t[0] = mulFe(p2[1], t[2]);
            t[8] = squareFe(p2[2]);
            t[3] = mulFe(p1[0], t[8]);
            t[4] = mulFe(p2[2], t[8]);
            t[2] = mulFe(p1[1], t[4]);

            if(t[1] == t[3]) {
                if(t[0] == t[2]) {
                    res = DoubleG1(p1);
                } else {
                    res = [0, r1, 0];
                }
            } else {
                t[1] = mod(t[1] - t[3], P);
                t[4] = mod(t[1] << 1, P);
                t[4] = squareFe(t[4]);
                t[5] = mulFe(t[1], t[4]);
                t[0] = mod(t[0] - t[2], P);
                t[0] = mod(t[0] << 1, P);
                t[6] = squareFe(t[0]);
                t[6] = mod(t[6] - t[5], P);
                t[3] = mulFe(t[3], t[4]);
                t[4] = mod(t[3] << 1, P);
                res[0] = mod(t[6] - t[4], P);
                t[4] = mod(t[3] - res[0], P);
                t[6] = mulFe(t[2], t[5]);
                t[6] = mod(t[6] << 1, P);
                t[0] = mulFe(t[0], t[4]);
                res[1] = mod(t[0] - t[6], P);
                t[0] = mod(p1[2] + p2[2], P);
                t[0] = squareFe(t[0]);
                t[0] = mod(t[0] - t[7], P);
                t[0] = mod(t[0] - t[8], P);
                res[2] = mulFe(t[0], t[1]);
            }
        }

        return res;
    }

	// http://www.hyperelliptic.org/EFD/gp/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    static function DoubleG1(PointG1 p) : PointG1 {
        PointG1 res = PtG1Zero;
        G1 t = G1Zero;

    	if(IsZeroG1(p)) {
		    res = p;
        } else {
            t[0] = squareFe(p[0]);
            t[1] = squareFe(p[1]);
            t[2] = squareFe(t[1]);
            t[1] = mod(p[0] + t[1], P);
            t[1] = squareFe(t[1]);
            t[1] = mod(t[1] - t[0], P);
            t[1] = mod(t[1] - t[2], P);
            t[1] = mod(t[1] << 1, P);
            t[3] = mod(t[0] << 1, P);
            t[0] = mod(t[3] + t[0], P);
            t[4] = squareFe(t[0]);
            t[3] = mod(t[1] << 1, P);
            res[0] = mod(t[4] - t[3], P);
            t[1] = mod(t[1] - res[0], P);
            t[2] = mod(t[2] << 1, P);
            t[2] = mod(t[2] << 1, P);
            t[2] = mod(t[2] << 1, P);
            t[0] = mulFe(t[0], t[1]);
            t[1] = mod(t[0] - t[2], P);
            t[0] = mulFe(p[1], p[2]);
            res[1] = t[1];
            res[2] = mod(t[0] << 1, P);
        }

        return res;
    }

    static function NegG1(PointG1 p) : PointG1 {
        return [p[0], mod(-p[1], P), p[2]];
    }

    static function MulScalarG1(PointG1 a, int e) : PointG1  {
        PointG1 res = [0, 1, 0];
        if (e != 0) {
            PointG1 t = PtG1Zero;
            PointG1 sum = PtG1Zero;
            bytes mb = reverseBytes(num2bin(e, S), S);
            bytes mm = b'00';
            bool firstOne = false;

            loop(256) : i {
                if (firstOne) {
                    t = DoubleG1(sum);
                }

                mm = mask << (255 - i);
                if ((mb & mm) != zero) {
                    firstOne = true;
                    sum = AddG1(t, a);
                } else {
                    sum = t;
                }
            }
            res = sum;
        }
        return res;
    }

    //--------------------- 
    static function ZeroG2() : PointG2 {
        return [zeroFe2(), oneFe2(), zeroFe2()];
    }

    static function IsZeroG2(PointG2 p) : bool {
        return isZeroFe2(p[2]);
    }

    static function IsAffineG2(PointG2 p) : bool {
        return isOneFe2(p[2]);
    }

    static function AffineG2(PointG2 p) : PointG2 {
        PointG2 res = p;

        if(IsZeroG2(p) == false) {
            if(IsAffineG2(p) == false) {
                G2 t = G2Zero;
                t[0] = inverseFe2(p[2]);
                t[1] = mulFe2(t[0], t[0]);
                p[0] = mulFe2(p[0], t[1]);
                t[0] = mulFe2(t[0], t[1]);
                p[1] = mulFe2(p[1], t[0]);
                p[2] = [r1, 0];

                res = p;
            }
        }
        return res;
    }
}
"#;

    let pairing_lib = r#"
struct Pair {PointG1 g1; PointG2 g2;}

library BLS12381Pairing {
    // 2 ^ (-1)
    static const fe twoInv = 0x17fbb8571a006596d3916126f2d14ca26e22d1ec31ebb502633cb57c253c276f855000053ab000011804000000015554;

    static const int x = 0xd201000000010000;
    static const bytes X = b'd201000000010000';
    static const bytes MASK = b'0000000000000001';
    static const bytes ZERO = b'0000000000000000';

    static const fe2 [10]Fe2_10Zero = repeat(BLS12381.Fe2Zero, 10);

    static function affinePair(PointG1 g1, PointG2 g2) : Pair {
        Pair pr = {BLS12381.PtG1Zero, BLS12381.Fe6Zero};
        if((BLS12381.IsZeroG1(g1) || BLS12381.IsZeroG2(g2)) == false) {
            pr = {BLS12381.AffineG1(g1), BLS12381.AffineG2(g2)};
        }
        return pr;
    }

    // Adaptation of Formula 3 in https://eprint.iacr.org/2010/526.pdf
    static function doublingStep(fe2 [3]coeff, PointG2 r) : fe12 {
        fe2 [10]t = Fe2_10Zero;
        fe6 rr = BLS12381.Fe6Zero;

        t[0] = BLS12381.mulFe2(r[0], r[1]);
        t[0] = BLS12381.mulByFqFe2(t[0], twoInv);
        t[1] = BLS12381.squareFe2(r[1]);
        t[2] = BLS12381.squareFe2(r[2]);
        t[7] = BLS12381.doubleFe2(t[2]);
        t[7] = BLS12381.addFe2(t[7], t[2]);
        t[3] = BLS12381.mulByBFe2(t[7]);
        t[4] = BLS12381.doubleFe2(t[3]);
        t[4] = BLS12381.addFe2(t[4], t[3]);
        t[5] = BLS12381.addFe2(t[1], t[4]);
        t[5] = BLS12381.mulByFqFe2(t[5], twoInv);
        t[6] = BLS12381.addFe2(r[1], r[2]);
        t[6] = BLS12381.squareFe2(t[6]);
        t[7] = BLS12381.addFe2(t[2], t[1]);
        t[6] = BLS12381.subFe2(t[6], t[7]);
        coeff[0] = BLS12381.subFe2(t[3], t[1]);
        t[7] = BLS12381.squareFe2(r[0]);
        t[4] = BLS12381.subFe2(t[1], t[4]);

        rr[0] = BLS12381.mulFe2(t[4], t[0]);

        t[2] = BLS12381.squareFe2(t[3]);
        t[3] = BLS12381.doubleFe2(t[2]);
        t[3] = BLS12381.addFe2(t[3], t[2]);
        t[5] = BLS12381.squareFe2(t[5]);
        rr[1] = BLS12381.subFe2(t[5], t[3]);
        rr[2] = BLS12381.mulFe2(t[1], t[6]);
        t[0] = BLS12381.doubleFe2(t[7]);
        coeff[1] = BLS12381.addFe2(t[0], t[7]);
        coeff[2] = BLS12381.negFe2(t[6]);

        return [coeff, rr];
    }

    // Algorithm 12 in https://eprint.iacr.org/2010/526.pdf
    static function additionStep(fe2[3] coeff, PointG2 r, PointG2 q) : fe12 {
        fe2 [10]t = Fe2_10Zero;

        t[0] = BLS12381.mulFe2(q[1], r[2]);
        t[0] = BLS12381.negFe2(t[0]);
        t[0] = BLS12381.addFe2(t[0], r[1]);
        t[1] = BLS12381.mulFe2(q[0], r[2]);
        t[1] = BLS12381.negFe2(t[1]);
        t[1] = BLS12381.addFe2(t[1], r[0]);
        t[2] = BLS12381.squareFe2(t[0]);
        t[3] = BLS12381.squareFe2(t[1]);
        t[4] = BLS12381.mulFe2(t[1], t[3]);
        t[2] = BLS12381.mulFe2(r[2], t[2]);
        t[3] = BLS12381.mulFe2(r[0], t[3]);
        t[5] = BLS12381.doubleFe2(t[3]);
        t[5] = BLS12381.subFe2(t[4], t[5]);
        t[5] = BLS12381.addFe2(t[5], t[2]);

        r[0] = BLS12381.mulFe2(t[1], t[5]);
        t[2] = BLS12381.subFe2(t[3], t[5]);
        t[2] = BLS12381.mulFe2(t[2], t[0]);
        t[3] = BLS12381.mulFe2(r[1], t[4]);
        r[1] = BLS12381.subFe2(t[2], t[3]);
        r[2] = BLS12381.mulFe2(r[2], t[4]);
        t[2] = BLS12381.mulFe2(t[1], q[1]);
        t[3] = BLS12381.mulFe2(t[0], q[0]);
        coeff[0] = BLS12381.subFe2(t[3], t[2]);
        coeff[1] = BLS12381.negFe2(t[0]);
        coeff[2] = t[1];

        return [coeff, r];
    }

    // Algorithm 5 in  https://eprint.iacr.org/2019/077.pdf
    // 101 0010 0000 0001 0000 0000 0000 0000 0000 0000 0000 0001 0000 0000 0000 0000;
    static function preCompute(fe6[68] ellCoeffs, PointG2 twistPoint) : fe6[68] {
        if(BLS12381.IsZeroG2(twistPoint) == false) {
            PointG2 r = twistPoint;
            int j = 0;

            fe12 rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;
            rtn = additionStep(ellCoeffs[j], r, twistPoint);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;
            rtn = additionStep(ellCoeffs[j], r, twistPoint);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;
            rtn = additionStep(ellCoeffs[j], r, twistPoint);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;
            rtn = additionStep(ellCoeffs[j], r, twistPoint);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;
            rtn = additionStep(ellCoeffs[j], r, twistPoint);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
            r = rtn[1];
            j++;

            rtn = doublingStep(ellCoeffs[j], r);
            ellCoeffs[j] = rtn[0];
        }

        return ellCoeffs;
    }

    // 101 0010 0000 0001 0000 0000 0000 0000 0000 0000 0000 0001 0000 0000 0000 0000;
    static function millerLoop(PointG1 g1, PointG2 g2) : fe12 {
        fe6[68] ellCoeffs = repeat(BLS12381.Fe6Zero, 68);
        
        ellCoeffs = preCompute(ellCoeffs, g2);

        fe12 f = BLS12381.oneFe12();
        fe2 [2]t2 = repeat(BLS12381.Fe2Zero, 2);
        int j = 0;

        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        j++;

        f = BLS12381.squareFe12(f);
        t2[0] = BLS12381.mulByFqFe2(ellCoeffs[j][2], g1[1]);
        t2[1] = BLS12381.mulByFqFe2(ellCoeffs[j][1], g1[0]);
        f = BLS12381.mulBy014AssignFe12(f, ellCoeffs[j][0], t2[1], t2[0]);
        // j++;

        f = BLS12381.conjugateFe12(f);
        return f;
    }


    static function expPair(fe12 a) : fe12 {
        // fe12 c = BLS12381.cyclotomicExp(a, x);
        fe12 c = BLS12381.cyclotomicExp2(a);
        c = BLS12381.conjugateFe12(c);
        return c;
    }

    static function finalExp(fe12 f) : fe12 {
        fe12 [9]t = repeat(BLS12381.Fe12Zero, 9);

        t[0] = BLS12381.frobeniusMapFe12(f, 6);

        t[1] = BLS12381.inverseFe12(f);

        t[2] = BLS12381.mulFe12(t[0], t[1]);
        t[1] = t[2];
        t[2] = BLS12381.frobeniusMapFe12(t[2], 2);
        t[2] = BLS12381.mulFe12(t[2], t[1]);
        t[1] = BLS12381.cyclotomicSquare(t[2]);
        t[1] = BLS12381.conjugateFe12(t[1]);

        // hard part
        t[3] = expPair(t[2]);

        t[4] = BLS12381.cyclotomicSquare(t[3]);
        t[5] = BLS12381.mulFe12(t[1], t[3]);
        t[1] = expPair(t[5]);
        t[0] = expPair(t[1]);
        t[6] = expPair(t[0]);

        t[6] = BLS12381.mulFe12(t[6], t[4]);
        t[4] = expPair(t[6]);
        t[5] = BLS12381.conjugateFe12(t[5]);
        t[4] = BLS12381.mulFe12(t[4], t[5]);
        t[4] = BLS12381.mulFe12(t[4], t[2]);
        
        t[5] = BLS12381.conjugateFe12(t[2]);
        t[1] = BLS12381.mulFe12(t[1], t[2]);
        t[1] = BLS12381.frobeniusMapFe12(t[1], 3);
        t[6] = BLS12381.mulFe12(t[6], t[5]);
        t[6] = BLS12381.frobeniusMapFe12(t[6], 1);

        t[3] = BLS12381.mulFe12(t[3], t[0]);
        t[3] = BLS12381.frobeniusMapFe12(t[3], 2);
        t[3] = BLS12381.mulFe12(t[3], t[1]);
        t[3] = BLS12381.mulFe12(t[3], t[6]);
        f = BLS12381.mulFe12(t[3], t[4]);
        return f;
    }
    
    // Check four pairs.
    // A * B + inputs * (-gamma) + C * (-delta) == alpha * beta
    static function pairCheck4Point(
            PointG1 a0, PointG2 b0,
            PointG1 a1, PointG2 b1,
            PointG1 a2, PointG2 b2,
            PointG1 a3, PointG2 b3) : bool {

        fe12 f1 = BLS12381.Fe12Zero;
        fe12 f2 = BLS12381.Fe12Zero;
        fe12 f3 = BLS12381.Fe12Zero;
        fe12 f0 = BLS12381.Fe12Zero;
        fe12 acc = BLS12381.Fe12Zero;

        Pair pair = affinePair(a1, b1);
        f1 = millerLoop(pair.g1, pair.g2);

        pair = affinePair(a2, b2);
        f2 = millerLoop(pair.g1, pair.g2);

        pair = affinePair(a3, b3);
        f3 = millerLoop(pair.g1, pair.g2);

        pair = affinePair(a0, b0);
        f0 = millerLoop(BLS12381.NegG1(pair.g1), pair.g2);

        acc = BLS12381.mulFe12(f1, f2);
        acc = BLS12381.mulFe12(acc, f3);
        acc = BLS12381.mulFe12(acc, f0);

        acc = finalExp(acc);

        return BLS12381.isOneFe12(acc);
    }

    // Check three pairs.
    // millerb1a1 + A * B + inputs * (-gamma) + C * (-delta) == 1
    static function pairCheck3Point(
            PointG1 a0, PointG2 b0,
            fe12 millerb1a1,
            PointG1 a2, PointG2 b2,
            PointG1 a3, PointG2 b3) : bool {

        fe12 f2 = BLS12381.Fe12Zero;
        fe12 f3 = BLS12381.Fe12Zero;
        fe12 f0 = BLS12381.Fe12Zero;
        fe12 acc = BLS12381.Fe12Zero;

        Pair pair = affinePair(a2, b2);
        f2 = millerLoop(pair.g1, pair.g2);

        pair = affinePair(a3, b3);
        f3 = millerLoop(pair.g1, pair.g2);

        pair = affinePair(a0, b0);
        f0 = millerLoop(BLS12381.NegG1(pair.g1), pair.g2);

        acc = BLS12381.mulFe12(millerb1a1, f2);
        acc = BLS12381.mulFe12(acc, f3);
        acc = BLS12381.mulFe12(acc, f0);

        acc = finalExp(acc);

        return BLS12381.isOneFe12(acc);
    }
}
"#;

    [
        bls12_381_lib,
        pairing_lib,
    ]
    .join("\n")
}