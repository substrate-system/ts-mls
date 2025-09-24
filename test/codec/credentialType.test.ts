import type { CredentialTypeName } from '../../src/credentialType'
import { encodeCredentialType, decodeCredentialType } from '../../src/credentialType'
import { createRoundtripTest } from './roundtrip.js'

describe('CredentialTypeName roundtrip', () => {
    const roundtrip = createRoundtripTest(encodeCredentialType, decodeCredentialType)

    test('roundtrips basic', () => {
        roundtrip('basic' as CredentialTypeName)
    })

    test('roundtrips x509', () => {
        roundtrip('x509' as CredentialTypeName)
    })
})
