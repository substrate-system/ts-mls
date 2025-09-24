import { concatUint8Arrays } from '../util/byteArray.js'
import { decodeUint8, encodeUint8 } from './number.js'
import type { Decoder } from './tlsDecoder.js'
import type { Encoder } from './tlsEncoder.js'

export function encodeOptional<T> (encodeT: Encoder<T>): Encoder<T | undefined> {
    return (t) => (t ? prependPresenceOctet(encodeT(t)) : new Uint8Array([0x0]))
}

export function decodeOptional<T> (decodeT: Decoder<T>): Decoder<T | undefined> {
    return (b, offset) => {
        const presenceOctet = decodeUint8(b, offset)?.[0]
        if (presenceOctet == 1) {
            const result = decodeT(b, offset + 1)
            return result === undefined ? undefined : [result[0], result[1] + 1]
        } else {
            return [undefined, 1]
        }
    }
}

function prependPresenceOctet (v: Uint8Array): Uint8Array {
    return concatUint8Arrays(encodeUint8(0x1), v)
}
