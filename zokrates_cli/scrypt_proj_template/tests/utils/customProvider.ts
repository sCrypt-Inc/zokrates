import { Provider, ProviderEvent, TransactionResponse, TxHash, bsv, UTXO, AddressOption, WhatsonchainProvider } from "scrypt-ts";
import { UtxoQueryOptions } from "scrypt-ts/dist/bsv/abstract-provider";
const superagent = require('superagent');


/**
 * The TaalProvider is backed by [taal]{@link https://console.taal.com/}, 
 * which is the popular blockchain exxplorer for Bitcoin.
 */
export class CustomProvider extends Provider {

    private _network: bsv.Networks.Network = bsv.Networks.testnet;

    private _provider: Provider;

    constructor(private apiKey: string = 'testnet_4df8757e4c289af199f69ad759be31b4') {
        super();

        if (this.apiKey.startsWith('testnet_')) {
            this._network = bsv.Networks.testnet
        } else {
            this._network = bsv.Networks.mainnet
        }
        this._provider = new WhatsonchainProvider(this._network);
    }

    get apiPrefix(): string {
        return `https://api.taal.com/api/v1/broadcast`;
    }

    isConnected(): boolean {
        return true;
    }

    connect(): Promise<this> {
        this.emit(ProviderEvent.Connected, true);
        return Promise.resolve(this);
    }

    updateNetwork(network: bsv.Networks.Network): Promise<boolean> {
        this._network = network;
        this.emit(ProviderEvent.NetworkChange, network);
        return Promise.resolve(true);
    }

    getNetwork(): Promise<bsv.Networks.Network> {
        return Promise.resolve(this._network);
    }

    async sendRawTransaction(rawTxHex: string): Promise<TxHash> {

        // 1 second per KB
        const size = Math.max(1, rawTxHex.length / 2 / 1024); //KB
        const timeout = Math.max(100000, 1000 * size);

        try {

            const res = await superagent.post('https://api.taal.com/api/v1/broadcast')
                .timeout({
                    response: timeout, 
                    deadline: 600000, 
                })
                .set('Content-Type', 'application/octet-stream')
                .set('Authorization', this.apiKey)
                .send(Buffer.from(rawTxHex, 'hex'))

            return res.text;
        } catch (error) {
            console.log(JSON.stringify(error))
            throw new Error(`TaalProvider ERROR: ${error.message}`)
        }
    }

    async listUnspent(address: AddressOption, options: UtxoQueryOptions): Promise<UTXO[]> {
        return this._provider.listUnspent(address, options);
    }

    getBalance(address?: AddressOption): Promise<{ confirmed: number, unconfirmed: number }> {
        return this._provider.getBalance(address);
    }

    getTransaction(txHash: string): Promise<TransactionResponse> {
        return this._provider.getTransaction(txHash);
    }


    getFeePerKb(): Promise<number> {
        return Promise.resolve(50);
    }

}