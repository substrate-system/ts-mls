import type { ClientState } from '../../src/clientState'
import { createGroup, joinGroup, makePskIndex } from '../../src/clientState'
import { createCommit } from '../../src/createCommit'
import { createApplicationMessage } from '../../src/createMessage'
import { processPrivateMessage } from '../../src/processMessages'
import { emptyPskIndex } from '../../src/pskIndex'
import type { Credential } from '../../src/credential'
import type { CiphersuiteImpl, CiphersuiteName } from '../../src/crypto/ciphersuite'
import { ciphersuites, getCiphersuiteFromName } from '../../src/crypto/ciphersuite'
import { getCiphersuiteImpl } from '../../src/crypto/getCiphersuiteImpl'
import { generateKeyPackage } from '../../src/keyPackage'
import type { ProposalAdd } from '../../src/proposal'
import { shuffledIndices, testEveryoneCanMessageEveryone } from './common.js'
import { defaultLifetime } from '../../src/lifetime'
import { defaultCapabilities } from '../../src/defaultCapabilities'
import type { PrivateMessage } from '../../src/privateMessage'
import type { KeyRetentionConfig } from '../../src/keyRetentionConfig'
import { defaultKeyRetentionConfig } from '../../src/keyRetentionConfig'
import { ValidationError } from '../../src/mlsError'
import { defaultClientConfig } from '../../src/clientConfig'

describe('Out of order message processing by generation', () => {
    test.concurrent.each(Object.keys(ciphersuites))('Out of order generation %s', async (cs) => {
        await generationOutOfOrder(cs as CiphersuiteName)
    })

    test.concurrent.each(Object.keys(ciphersuites))('Out of order generation random %s', async (cs) => {
        await generationOutOfOrderRandom(cs as CiphersuiteName, defaultKeyRetentionConfig.retainKeysForGenerations)
    })

    test.concurrent.each(Object.keys(ciphersuites))('Out of order generation limit reached fails %s', async (cs) => {
        await generationOutOfOrderLimitFails(cs as CiphersuiteName, 10)
    })
})

type TestParticipants = {
  aliceGroup: ClientState
  bobGroup: ClientState
  impl: CiphersuiteImpl
}

async function setupTestParticipants (
    cipherSuite: CiphersuiteName,
    retainConfig?: KeyRetentionConfig,
): Promise<TestParticipants> {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

    const aliceCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('alice') }
    const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

    const groupId = new TextEncoder().encode('group1')
    let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

    const bobCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('bob') }
    const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

    const addBobProposal: ProposalAdd = {
        proposalType: 'add',
        add: {
            keyPackage: bob.publicPackage,
        },
    }

    const addBobCommitResult = await createCommit(
        {
            state: aliceGroup,
            cipherSuite: impl,
        },
        {
            extraProposals: [addBobProposal],
            ratchetTreeExtension: true,
        },
    )
    aliceGroup = addBobCommitResult.newState

    const bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    undefined,
    undefined,
    { ...defaultClientConfig, keyRetentionConfig: retainConfig ?? defaultClientConfig.keyRetentionConfig },
    )

    return { aliceGroup, bobGroup, impl }
}

async function generationOutOfOrder (cipherSuite: CiphersuiteName) {
    const { aliceGroup: initialAliceGroup, bobGroup: initialBobGroup, impl } = await setupTestParticipants(cipherSuite)

    let aliceGroup = initialAliceGroup
    let bobGroup = initialBobGroup

    const firstMessage = new TextEncoder().encode('Hello bob!')
    const secondMessage = new TextEncoder().encode('How are ya?')
    const thirdMessage = new TextEncoder().encode('Have you heard the news?')

    // alice sends the first message
    const aliceCreateFirstMessageResult = await createApplicationMessage(aliceGroup, firstMessage, impl)
    aliceGroup = aliceCreateFirstMessageResult.newState

    const aliceCreateSecondMessageResult = await createApplicationMessage(aliceGroup, secondMessage, impl)
    aliceGroup = aliceCreateSecondMessageResult.newState

    const aliceCreateThirdMessageResult = await createApplicationMessage(aliceGroup, thirdMessage, impl)
    aliceGroup = aliceCreateThirdMessageResult.newState

    // bob receives 3rd message first
    const bobProcessThirdMessageResult = await processPrivateMessage(
        bobGroup,
        aliceCreateThirdMessageResult.privateMessage,
        makePskIndex(bobGroup, {}),
        impl,
    )
    bobGroup = bobProcessThirdMessageResult.newState

    // then bob receives the first message
    const bobProcessFirstMessageResult = await processPrivateMessage(
        bobGroup,
        aliceCreateFirstMessageResult.privateMessage,
        makePskIndex(bobGroup, {}),
        impl,
    )
    bobGroup = bobProcessFirstMessageResult.newState

    // bob receives 2nd message last
    const bobProcessSecondMessageResult = await processPrivateMessage(
        bobGroup,
        aliceCreateSecondMessageResult.privateMessage,
        makePskIndex(bobGroup, {}),
        impl,
    )
    bobGroup = bobProcessSecondMessageResult.newState

    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}

async function generationOutOfOrderRandom (cipherSuite: CiphersuiteName, totalMessages: number) {
    const { aliceGroup: initialAliceGroup, bobGroup: initialBobGroup, impl } = await setupTestParticipants(cipherSuite)

    let aliceGroup = initialAliceGroup
    let bobGroup = initialBobGroup

    const message = new TextEncoder().encode('Hi!')

    const messages: PrivateMessage[] = []
    for (let i = 0; i < totalMessages; i++) {
        const createMessageResult = await createApplicationMessage(aliceGroup, message, impl)
        aliceGroup = createMessageResult.newState
        messages.push(createMessageResult.privateMessage)
    }

    const shuffledMessages = shuffledIndices(messages).map((i) => messages[i]!)

    for (const msg of shuffledMessages) {
        const bobProcessMessageResult = await processPrivateMessage(bobGroup, msg, makePskIndex(bobGroup, {}), impl)
        bobGroup = bobProcessMessageResult.newState
    }

    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}

async function generationOutOfOrderLimitFails (cipherSuite: CiphersuiteName, totalMessages: number) {
    const retainConfig = { ...defaultKeyRetentionConfig, retainKeysForGenerations: totalMessages - 1 }
    const {
        aliceGroup: initialAliceGroup,
        bobGroup: initialBobGroup,
        impl,
    } = await setupTestParticipants(cipherSuite, retainConfig)

    let aliceGroup = initialAliceGroup
    let bobGroup = initialBobGroup

    const message = new TextEncoder().encode('Hi!')

    const messages: PrivateMessage[] = []
    for (let i = 0; i < totalMessages + 1; i++) {
        const createMessageResult = await createApplicationMessage(aliceGroup, message, impl)
        aliceGroup = createMessageResult.newState
        messages.push(createMessageResult.privateMessage)
    }

    // read the last message first
    const processResult = await processPrivateMessage(bobGroup, messages.at(-1)!, emptyPskIndex, impl)
    bobGroup = processResult.newState

    // should fail reading the first message
    await expect(processPrivateMessage(bobGroup, messages.at(0)!, emptyPskIndex, impl)).rejects.toThrow(ValidationError)
}
