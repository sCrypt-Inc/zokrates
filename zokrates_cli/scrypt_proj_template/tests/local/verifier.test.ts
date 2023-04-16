import { expect } from 'chai'
import { Verifier } from '../../src/contracts/verifier'
import { N_PUB_INPUTS, Proof, VERIFYING_KEY_DATA } from '../../src/contracts/snark'
import { prepareVerifyingKey, parseProofFile } from '../../src/util'
import { FixedArray } from 'scrypt-ts'

describe('Test G16 on BN256', () => {

    let verifier = undefined

    before(async () => {
        await Verifier.compile()
        verifier = new Verifier(
            prepareVerifyingKey(VERIFYING_KEY_DATA)
        )
    })

    it('should pass verify proof', () => {
        // TODO: Link proof.json (relative to project root dir)
        const proofPath = '../proof.json'
        const proof: Proof = parseProofFile(proofPath)

        // TODO: Insert public param values here:
        const inputs: FixedArray<bigint, typeof N_PUB_INPUTS> = [ 0n ]

        const result = verifier.verify((self) => {
            self.verifyProof(inputs, proof)
        })
        expect(result.success, result.error).to.be.true
    })
})
