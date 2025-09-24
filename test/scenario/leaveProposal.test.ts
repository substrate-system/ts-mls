import { createGroup, joinGroup } from '../../src/clientState'
import { createCommit } from '../../src/createCommit'
import { createProposal } from '../../src/createMessage'
import { emptyPskIndex } from '../../src/pskIndex'
import type { Credential } from '../../src/credential'
import type { CiphersuiteName } from '../../src/crypto/ciphersuite'
import { ciphersuites, getCiphersuiteFromName } from '../../src/crypto/ciphersuite'
import { getCiphersuiteImpl } from '../../src/crypto/getCiphersuiteImpl'
import { generateKeyPackage } from '../../src/keyPackage'
import type { Proposal, ProposalAdd } from '../../src/proposal'
import { checkHpkeKeysMatch } from '../crypto/keyMatch'
import { cannotMessageAnymore, testEveryoneCanMessageEveryone } from './common.js'
import { defaultLifetime } from '../../src/lifetime'
import { defaultCapabilities } from '../../src/defaultCapabilities'
import type { WireformatName } from '../../src/wireformat'
import { processMessage } from '../../src/processMessages'
import { acceptAll } from '../../src/incomingMessageAction'

test.concurrent.each(Object.keys(ciphersuites))('Leave Proposal %s', async (cs) => {
    await leaveProposal(cs as CiphersuiteName, true)
    await leaveProposal(cs as CiphersuiteName, false)
})

async function leaveProposal (cipherSuite: CiphersuiteName, publicMessage: boolean) {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

    const aliceCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('alice') }
    const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

    const preferredWireformat: WireformatName = publicMessage ? 'mls_public_message' : 'mls_private_message'
    const groupId = new TextEncoder().encode('group1')

    let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

    const bobCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('bob') }
    const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

    const charlieCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('charlie') }
    const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities(), defaultLifetime, [], impl)

    const addBobProposal: ProposalAdd = {
        proposalType: 'add',
        add: {
            keyPackage: bob.publicPackage,
        },
    }

    const addCharlieProposal: ProposalAdd = {
        proposalType: 'add',
        add: {
            keyPackage: charlie.publicPackage,
        },
    }

    const addBobAndCharlieCommitResult = await createCommit(
        {
            state: aliceGroup,
            cipherSuite: impl,
        },
        {
            wireAsPublicMessage: publicMessage,
            extraProposals: [addBobProposal, addCharlieProposal],
            ratchetTreeExtension: true,
        },
    )

    aliceGroup = addBobAndCharlieCommitResult.newState

    let bobGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    )

    expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    let charlieGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    emptyPskIndex,
    impl,
    )

    expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    const leaveProposal: Proposal = {
        proposalType: 'remove',
        remove: { removed: aliceGroup.privatePath.leafIndex },
    }

    const createLeaveProposalResult = await createProposal(aliceGroup, publicMessage, leaveProposal, impl)

    aliceGroup = createLeaveProposalResult.newState

    if (createLeaveProposalResult.message.wireformat !== preferredWireformat) { throw new Error(`Expected ${preferredWireformat} message`) }

    const bobProcessProposalResult = await processMessage(
        createLeaveProposalResult.message,
        bobGroup,
        emptyPskIndex,
        acceptAll,
        impl,
    )

    bobGroup = bobProcessProposalResult.newState

    const charlieProcessProposalResult = await processMessage(
        createLeaveProposalResult.message,
        charlieGroup,
        emptyPskIndex,
        acceptAll,
        impl,
    )

    charlieGroup = charlieProcessProposalResult.newState

    // bob commits to alice leaving
    const bobCommitResult = await createCommit(
        {
            state: bobGroup,
            cipherSuite: impl,
        },
        {
            wireAsPublicMessage: publicMessage,
            ratchetTreeExtension: false,
        },
    )

    bobGroup = bobCommitResult.newState

    if (bobCommitResult.commit.wireformat !== preferredWireformat) { throw new Error(`Expected ${preferredWireformat} message`) }

    const aliceProcessCommitResult = await processMessage(
        bobCommitResult.commit,
        aliceGroup,
        emptyPskIndex,
        acceptAll,
        impl,
    )
    aliceGroup = aliceProcessCommitResult.newState

    const charlieProcessCommitResult = await processMessage(
        bobCommitResult.commit,
        charlieGroup,
        emptyPskIndex,
        acceptAll,
        impl,
    )
    charlieGroup = charlieProcessCommitResult.newState

    expect(bobGroup.unappliedProposals).toEqual({})
    expect(charlieGroup.unappliedProposals).toEqual({})
    expect(aliceGroup.groupActiveState).toStrictEqual({ kind: 'removedFromGroup' })

    await cannotMessageAnymore(aliceGroup, impl)
    await checkHpkeKeysMatch(bobGroup, impl)
    await checkHpkeKeysMatch(charlieGroup, impl)
    await testEveryoneCanMessageEveryone([bobGroup, charlieGroup], impl)
}
