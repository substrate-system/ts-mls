import { encodePublicMessage, decodePublicMessage } from '../../src/publicMessage'
import { createRoundtripTest } from './roundtrip.js'

describe('PublicMessage roundtrip', () => {
    const roundtrip = createRoundtripTest(encodePublicMessage, decodePublicMessage)

    test('roundtrips member', () => {
        roundtrip({
            content: {
                contentType: 'application',
                groupId: new Uint8Array([1]),
                epoch: 0n,
                sender: { senderType: 'member', leafIndex: 0 },
                authenticatedData: new Uint8Array([2]),
                applicationData: new Uint8Array([3]),
            },
            auth: { contentType: 'application', signature: new Uint8Array([4, 5, 6]) },
            senderType: 'member',
            membershipTag: new Uint8Array([7, 8, 9]),
        })
    })

    test('roundtrips external', () => {
        roundtrip({
            content: {
                contentType: 'commit',
                groupId: new Uint8Array([10, 11]),
                epoch: 1n,
                sender: { senderType: 'external', senderIndex: 1 },
                authenticatedData: new Uint8Array([12, 13]),
                commit: { proposals: [], path: undefined },
            },
            auth: {
                contentType: 'commit',
                signature: new Uint8Array([14, 15, 16]),
                confirmationTag: new Uint8Array([17, 18, 19]),
            },
            senderType: 'external',
        })
    })
})
