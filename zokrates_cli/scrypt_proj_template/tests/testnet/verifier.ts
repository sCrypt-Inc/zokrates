
import { Verifier } from '../../src/contracts/verifier'
import { N_PUB_INPUTS, Proof, VERIFYING_KEY_DATA } from '../../src/contracts/snark'
import { parseProofFile, prepareVerifyingKey } from '../../src/util'
import { FixedArray } from 'scrypt-ts'
import { getDefaultSigner } from '../utils/helper'

const contractBalance = 1000

async function main() {
    await Verifier.compile()

    // TODO: Insert public input values here:
    const publicInputs: FixedArray<bigint, typeof N_PUB_INPUTS> = [ 0n ]

    let verifier = new Verifier(
        prepareVerifyingKey(VERIFYING_KEY_DATA),
        publicInputs
    )

    // Connect to a signer.
    const signer = getDefaultSigner()
    await verifier.connect(getDefaultSigner())

    // Deploy:
    const deployTx = await verifier.deploy(contractBalance)
    console.log('Verifier contract deployed: ', deployTx.id)

    // Call:
    // TODO: Link proof.json (relative to project root dir)
    const proofPath = '../proof.json'
    const proof: Proof = parseProofFile(proofPath)

    const { tx: callTx } = await verifier.methods.verifyProof(
        proof
    )
    console.log('Verifier contract unlocked: ', callTx.id)
}

describe('Test SmartContract `Verifier` on testnet', () => {
    it('should succeed', async () => {
        await main()
    })
})