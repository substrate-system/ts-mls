import type { ProtocolVersionName } from '../../src/protocolVersion'
import { encodeProtocolVersion, decodeProtocolVersion } from '../../src/protocolVersion'
import { createRoundtripTest } from './roundtrip.js'

describe('ProtocolVersionName roundtrip', () => {
    const roundtrip = createRoundtripTest(encodeProtocolVersion, decodeProtocolVersion)

    test('roundtrips mls10', () => {
        roundtrip('mls10' as ProtocolVersionName)
    })
})
