import type { ExternalSender } from '../../src/externalSender'
import { encodeExternalSender, decodeExternalSender } from '../../src/externalSender'
import { createRoundtripTest } from './roundtrip.js'

const basic: ExternalSender = {
    signaturePublicKey: new Uint8Array([1, 2, 3]),
    credential: { credentialType: 'basic', identity: new Uint8Array([4, 5, 6]) },
}

const x509: ExternalSender = {
    signaturePublicKey: new Uint8Array([7, 8, 9, 10, 11]),
    credential: { credentialType: 'x509', certificates: [new Uint8Array([12, 13]), new Uint8Array([14, 15, 16])] },
}

describe('ExternalSender roundtrip', () => {
    const roundtrip = createRoundtripTest(encodeExternalSender, decodeExternalSender)

    test('roundtrips basic', () => {
        roundtrip(basic)
    })

    test('roundtrips x509', () => {
        roundtrip(x509)
    })
})
