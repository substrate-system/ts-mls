import type { HPKECiphertext } from '../../src/hpkeCiphertext'
import { encodeHpkeCiphertext, decodeHpkeCiphertext } from '../../src/hpkeCiphertext'
import { createRoundtripTest } from './roundtrip.js'

const dummy: HPKECiphertext = {
    kemOutput: new Uint8Array([1, 2, 3]),
    ciphertext: new Uint8Array([4, 5, 6]),
}

describe('HPKECiphertext roundtrip', () => {
    const roundtrip = createRoundtripTest(encodeHpkeCiphertext, decodeHpkeCiphertext)

    test('roundtrips', () => {
        roundtrip(dummy)
    })
})
