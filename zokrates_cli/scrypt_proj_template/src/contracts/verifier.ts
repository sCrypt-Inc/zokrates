import { assert, SmartContract, method, prop, FixedArray } from 'scrypt-ts'
import { N_PUB_INPUTS, Proof, SNARK, VerifyingKey } from './snark'

export class Verifier extends SmartContract {

    @prop()
    vk: VerifyingKey

    @prop()
    publicInputs: FixedArray<bigint, typeof N_PUB_INPUTS>

    constructor(
        vk: VerifyingKey,
        publicInputs: FixedArray<bigint, typeof N_PUB_INPUTS>,
    ) {
        super(...arguments)
        this.vk = vk
        this.publicInputs = publicInputs
    }

    @method()
    public verifyProof(
        proof: Proof
    ) {
        assert(SNARK.verify(this.vk, this.publicInputs, proof))
    }

}
