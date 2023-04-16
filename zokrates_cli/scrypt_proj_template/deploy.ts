import { FixedArray } from 'scrypt-ts'
import { prepareVerifyingKey } from './src/util'
import { Verifier } from './src/contracts/verifier'
import { VERIFYING_KEY_DATA, N_PUB_INPUTS } from './src/contracts/snark'
import { getDefaultSigner } from './tests/utils/helper'

async function main() {
    await Verifier.compile()
    
    // TODO: Adjust the amount of satoshis locked in the smart contract:
    const amount = 100

    // TODO: Insert public input values here:
    const publicInputs: FixedArray<bigint, typeof N_PUB_INPUTS> = [ 0n ]

    let verifier = new Verifier(
        prepareVerifyingKey(VERIFYING_KEY_DATA),
        publicInputs
    )

    // Connect to a signer.
    await verifier.connect(getDefaultSigner())

    // Deploy:
    const deployTx = await verifier.deploy(amount)
    console.log('Verifier contract deployed: ', deployTx.id)
}

main()