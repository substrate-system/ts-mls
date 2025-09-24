import { createGroup, joinGroup, makePskIndex } from '../../src/clientState'
import { createCommit } from '../../src/createCommit'
import { processPrivateMessage } from '../../src/processMessages'
import { emptyPskIndex } from '../../src/pskIndex'
import type { Credential } from '../../src/credential'
import type { CiphersuiteName } from '../../src/crypto/ciphersuite'
import { ciphersuites, getCiphersuiteFromName } from '../../src/crypto/ciphersuite'
import { getCiphersuiteImpl } from '../../src/crypto/getCiphersuiteImpl'
import { generateKeyPackage } from '../../src/keyPackage'
import type { ProposalAdd, ProposalRemove } from '../../src/proposal'
import { checkHpkeKeysMatch } from '../crypto/keyMatch'
import { cannotMessageAnymore, testEveryoneCanMessageEveryone } from './common.js'
import { defaultLifetime } from '../../src/lifetime'
import { defaultCapabilities } from '../../src/defaultCapabilities'
import { UsageError } from '../../src/mlsError'

test.concurrent.each(Object.keys(ciphersuites))('Remove %s', async (cs) => {
    await remove(cs as CiphersuiteName)
})

async function remove (cipherSuite: CiphersuiteName) {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

    const aliceCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('alice') }
    const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

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
            extraProposals: [addBobProposal, addCharlieProposal],
        },
    )

    aliceGroup = addBobAndCharlieCommitResult.newState

    let bobGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
    )

    expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    let charlieGroup = await joinGroup(
    addBobAndCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
    )

    expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    const removeBobProposal: ProposalRemove = {
        proposalType: 'remove',
        remove: {
            removed: bobGroup.privatePath.leafIndex,
        },
    }

    const removeBobCommitResult = await createCommit(
        {
            state: aliceGroup,
            cipherSuite: impl,
        },
        {
            extraProposals: [removeBobProposal],
        },
    )

    aliceGroup = removeBobCommitResult.newState

    if (removeBobCommitResult.commit.wireformat !== 'mls_private_message') throw new Error('Expected private message')

    const bobProcessCommitResult = await processPrivateMessage(
        bobGroup,
        removeBobCommitResult.commit.privateMessage,
        makePskIndex(bobGroup, {}),
        impl,
    )

    // bob is removed here
    bobGroup = bobProcessCommitResult.newState

    const charlieProcessCommitResult = await processPrivateMessage(
        charlieGroup,
        removeBobCommitResult.commit.privateMessage,
        makePskIndex(charlieGroup, {}),
        impl,
    )

    charlieGroup = charlieProcessCommitResult.newState

    expect(bobGroup.groupActiveState).toStrictEqual({ kind: 'removedFromGroup' })

    // creating a message will fail now
    await expect(
        createCommit({
            state: bobGroup,
            cipherSuite: impl,
        }),
    ).rejects.toThrow(UsageError)

    await cannotMessageAnymore(bobGroup, impl)

    await checkHpkeKeysMatch(aliceGroup, impl)
    await checkHpkeKeysMatch(charlieGroup, impl)
    await testEveryoneCanMessageEveryone([aliceGroup, charlieGroup], impl)
}
