import type { ContentTypeName } from '../../src/contentType'
import { encodeContentType, decodeContentType } from '../../src/contentType'
import { createRoundtripTest } from './roundtrip.js'

describe('ContentTypeName roundtrip', () => {
    const roundtrip = createRoundtripTest(encodeContentType, decodeContentType)

    test('roundtrips minimal', () => {
        roundtrip('application' as ContentTypeName)
    })

    test('roundtrips nontrivial', () => {
        roundtrip('commit' as ContentTypeName)
    })
})
