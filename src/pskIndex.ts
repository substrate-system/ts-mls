import type { CiphersuiteImpl } from './crypto/ciphersuite.js'
import { ValidationError } from './mlsError.js'
import type { PreSharedKeyID } from './presharedkey.js'
import { updatePskSecret } from './presharedkey.js'

export interface PskIndex {
  findPsk(preSharedKeyId: PreSharedKeyID): Uint8Array | undefined
}
export const emptyPskIndex: PskIndex = {
    findPsk (_preSharedKeyId) {
        return undefined
    },
}

export async function accumulatePskSecret (
    groupedPsk: PreSharedKeyID[],
    pskSearch: PskIndex,
    cs: CiphersuiteImpl,
    zeroes: Uint8Array,
): Promise<[Uint8Array, PreSharedKeyID[]]> {
    return groupedPsk.reduce<Promise<[Uint8Array, PreSharedKeyID[]]>>(
        async (acc, cur, index) => {
            const [previousSecret, ids] = await acc
            const psk = pskSearch.findPsk(cur)
            if (psk === undefined) throw new ValidationError('Could not find pskId referenced in proposal')
            const pskSecret = await updatePskSecret(previousSecret, cur, psk, index, groupedPsk.length, cs)
            return [pskSecret, [...ids, cur]]
        },
        Promise.resolve([zeroes, []]),
    )
}
