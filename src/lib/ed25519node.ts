import * as crypto from 'crypto';
const HIGHEST_BIT = 0x80000000;

interface IDerive{
    privateKey: Buffer,
    chainCode: Buffer,
    deriveHardened(index: number): IDerive,
    derive(index: number): IDerive,
}

export class Ed25519Node implements IDerive {
    constructor(public privateKey: Buffer, public chainCode: Buffer){}
    derive(index: number): IDerive{
        const isHardened = index >= HIGHEST_BIT;
        if(!isHardened){
            throw new Error('ed25519 derive support is hardend only')
        }
        return CKDPriv(this, index)
    }
    deriveHardened(index: number): IDerive{
        return this.derive(index + HIGHEST_BIT)
    }
    derivePath(path: string): IDerive{
        const splitPath = path.split('/');
        if (splitPath[0] === 'm') {
            return derivePath(this, splitPath.slice(1))
        }
        return derivePath(this, splitPath)
    }
}

export const fromSeed = (seed: Buffer): Ed25519Node => {
    if (seed.length < 16) throw new TypeError('Seed should be at least 128 bits')
    if (seed.length > 64) throw new TypeError('Seed should be at most 512 bits')

    const I = crypto.createHmac('sha512', Buffer.from('ed25519 seed', 'utf8'))
        .update(seed)
        .digest()
    const IL = I.slice(0, 32)
    const IR = I.slice(32)

    return new Ed25519Node(IL, IR)
}

export const CKDPriv = (node: IDerive, index: number): IDerive => {
    const h = Buffer.alloc(1, 0)
    const i = Buffer.allocUnsafe(4);
    i.writeUInt32BE(index, 0);
    const data = Buffer.concat([h, node.privateKey, i]);

    const I = crypto.createHmac('sha512', node.chainCode)
        .update(data)
        .digest()
    const IL = I.slice(0, 32)
    const IR = I.slice(32)

    return new Ed25519Node(IL, IR)
}

export const derivePath = (node: IDerive, splitPath: string[]): IDerive => {
    return splitPath.reduce((prevHd: IDerive, indexStr: string) => {
        if (indexStr.slice(-1) === `'`) {
            const index = parseInt(indexStr.slice(0, -1), 10);
            return prevHd.deriveHardened(index);
        } else {
            const index = parseInt(indexStr, 10);
            return prevHd.derive(index);
        }
    }, node);
}

