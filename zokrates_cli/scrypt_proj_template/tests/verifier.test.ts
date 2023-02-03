import { expect } from 'chai'
import { Verifier, G1Point, Proof, VERIFYING_KEY_DATA, BN256, BN256Pairing, VerifyingKey } from '../src/contracts/verifier'
import { FixedArray } from 'scrypt-ts'

describe('Test G16 on BN256', () => {
    
    let verifier = undefined

    before(async () => {
        await Verifier.compile()
        // Construct VerifyingKey struct with pre-calculated miller(beta, alpha)
        let alpha = BN256.createCurvePoint(VERIFYING_KEY_DATA.alpha)
        let beta = BN256.createTwistPoint(VERIFYING_KEY_DATA.beta)
        let millerb1a1 = BN256Pairing.miller(beta, alpha)
        
        let vk: VerifyingKey = {
           millerb1a1: millerb1a1,
           gamma: VERIFYING_KEY_DATA.gamma,
           delta: VERIFYING_KEY_DATA.delta,
           gammaAbc: VERIFYING_KEY_DATA.gammaAbc
        }
        
        verifier = new Verifier(vk)
    })

    it('should pass verify proof', () => {
        // TODO: Insert proof values here:
        const proof: Proof = {
            a: {
                x: 0n,
                y: 0n,
            },
            b: {
                x: {
                    x: 0n,
                    y: 0n,
                },
                y: {
                    x: 0n,
                    y: 0n,
                },
            },
            c: {
                x: 0n,
                y: 0n,
            },
        }

        // TODO: Insert public param values here (don't forget to adjust arr size):
        const inputs: FixedArray<bigint, 1> = [ 0n ]

        const result = verifier.verify((self) => {
            self.verifyProof(inputs, proof)
        })
        expect(result.success, result.error).to.be.true
    })
})