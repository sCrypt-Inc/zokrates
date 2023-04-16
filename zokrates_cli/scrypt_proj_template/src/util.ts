import { PathLike, readFileSync } from "fs";
import { BN256, BN256Pairing, Proof, VerifyingKey, VERIFYING_KEY_DATA } from "./contracts/snark";

export function parseProofFile(path: PathLike): Proof {
    const data = readFileSync(path, 'utf-8');
    const parsedJSON = JSON.parse(data);

    const proof: Proof = {
        a: {
            x: BigInt(parsedJSON['proof']['a'][0]),
            y: BigInt(parsedJSON['proof']['a'][1]),
        },
        b: {
            x: {
                x: BigInt(parsedJSON['proof']['b'][0][0]),
                y: BigInt(parsedJSON['proof']['b'][0][1]),
            },
            y: {
                x: BigInt(parsedJSON['proof']['b'][1][0]),
                y: BigInt(parsedJSON['proof']['b'][1][1]),
            },
        },
        c: {
            x: BigInt(parsedJSON['proof']['c'][0]),
            y: BigInt(parsedJSON['proof']['c'][1]),
        },
    }

    return proof
}

export function prepareVerifyingKey(data: object): VerifyingKey {
    // Construct VerifyingKey struct with pre-calculated miller(beta, alpha).
    let alpha = BN256.createCurvePoint(VERIFYING_KEY_DATA.alpha)
    let beta = BN256.createTwistPoint(VERIFYING_KEY_DATA.beta)
    let millerb1a1 = BN256Pairing.miller(beta, alpha)

    let vk: VerifyingKey = {
        millerb1a1: millerb1a1,
        gamma: VERIFYING_KEY_DATA.gamma,
        delta: VERIFYING_KEY_DATA.delta,
        gammaAbc: VERIFYING_KEY_DATA.gammaAbc
    }
    
    return vk
}
