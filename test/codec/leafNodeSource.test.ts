import type { LeafNodeSourceName } from '../../src/leafNodeSource'
import { encodeLeafNodeSource, decodeLeafNodeSource } from '../../src/leafNodeSource'
import { createRoundtripTest } from './roundtrip.js'

describe('LeafNodeSourceName roundtrip', () => {
    const roundtrip = createRoundtripTest(encodeLeafNodeSource, decodeLeafNodeSource)

    test('roundtrips key_package', () => {
        roundtrip('key_package' as LeafNodeSourceName)
    })

    test('roundtrips commit', () => {
        roundtrip('commit' as LeafNodeSourceName)
    })

    test('roundtrips update', () => {
        roundtrip('update' as LeafNodeSourceName)
    })
})
