import { expect } from 'chai'
import { Verifier, Proof } from '../src/contracts/verifier'
import { FixedArray } from 'scrypt-ts'

describe('Test G16 on BN256', () => {
    let verifier = undefined

    before(async () => {
        await Verifier.compile()
        verifier = new Verifier()
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