import { assert, SmartContract, method, prop, FixedArray } from 'scrypt-ts'
import { N_PUB_INPUTS, Proof, SNARK, VerifyingKey } from './snark'

export class Verifier extends SmartContract {
    
    @prop()
    vk: VerifyingKey

    constructor(vk: VerifyingKey) {
        super(...arguments)
        this.vk = vk
    }
    
    @method()
    public verifyProof(
        inputs: FixedArray<bigint, typeof N_PUB_INPUTS>,
        proof: Proof,
    ) {
        assert(SNARK.verify(this.vk, inputs, proof))
    }

}
