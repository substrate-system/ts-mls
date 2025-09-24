import type { DefaultProposalTypeName } from '../../src/defaultProposalType'
import {
    encodeDefaultProposalType,
    decodeDefaultProposalType
} from '../../src/defaultProposalType'
import { createRoundtripTest } from './roundtrip.js'

describe('ProposalTypeName roundtrip', () => {
    const roundtrip = createRoundtripTest(encodeDefaultProposalType, decodeDefaultProposalType)

    test('roundtrips add', () => {
        roundtrip('add' as DefaultProposalTypeName)
    })

    test('roundtrips group_context_extensions', () => {
        roundtrip('group_context_extensions' as DefaultProposalTypeName)
    })
})
