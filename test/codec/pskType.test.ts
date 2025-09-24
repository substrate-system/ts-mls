import type { PSKTypeName } from '../../src/presharedkey'
import { encodePskType, decodePskType } from '../../src/presharedkey'
import { createRoundtripTest } from './roundtrip.js'

describe('PSKTypeName roundtrip', () => {
    const roundtrip = createRoundtripTest(encodePskType, decodePskType)

    test('roundtrips external', () => {
        roundtrip('external' as PSKTypeName)
    })

    test('roundtrips resumption', () => {
        roundtrip('resumption' as PSKTypeName)
    })
})
