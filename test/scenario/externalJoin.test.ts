import { createGroup, joinGroup, makePskIndex } from '../../src/clientState'
import { createGroupInfoWithExternalPubAndRatchetTree, joinGroupExternal, createCommit } from '../../src/createCommit'
import { processPublicMessage } from '../../src/processMessages'
import { emptyPskIndex } from '../../src/pskIndex'
import type { Credential } from '../../src/credential'
import type { CiphersuiteName } from '../../src/crypto/ciphersuite'
import { getCiphersuiteFromName, ciphersuites } from '../../src/crypto/ciphersuite'
import { getCiphersuiteImpl } from '../../src/crypto/getCiphersuiteImpl'
import { generateKeyPackage } from '../../src/keyPackage'
import type { ProposalAdd } from '../../src/proposal'
import { checkHpkeKeysMatch } from '../crypto/keyMatch'
import { testEveryoneCanMessageEveryone } from './common.js'
import { defaultLifetime } from '../../src/lifetime'
import { defaultCapabilities } from '../../src/defaultCapabilities'

test.concurrent.each(Object.keys(ciphersuites))('External join %s', async (cs) => {
    await externalJoin(cs as CiphersuiteName)
})

async function externalJoin (cipherSuite: CiphersuiteName) {
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

    const addBobCommitResult = await createCommit(
        {
            state: aliceGroup,
            cipherSuite: impl,
        },
        {
            extraProposals: [addBobProposal],
        },
    )

    aliceGroup = addBobCommitResult.newState

    let bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
    )

    expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    const groupInfo = await createGroupInfoWithExternalPubAndRatchetTree(aliceGroup, [], impl)

    const charlieJoinGroupCommitResult = await joinGroupExternal(
        groupInfo,
        charlie.publicPackage,
        charlie.privatePackage,
        false,
        impl,
    )

    const charlieGroup = charlieJoinGroupCommitResult.newState

    const aliceProcessCharlieJoinResult = await processPublicMessage(
        aliceGroup,
        charlieJoinGroupCommitResult.publicMessage,
        makePskIndex(aliceGroup, {}),
        impl,
    )

    aliceGroup = aliceProcessCharlieJoinResult.newState

    const bobProcessCharlieJoinResult = await processPublicMessage(
        bobGroup,
        charlieJoinGroupCommitResult.publicMessage,
        makePskIndex(bobGroup, {}),
        impl,
    )

    bobGroup = bobProcessCharlieJoinResult.newState

    expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
    expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(bobGroup.keySchedule.epochAuthenticator)

    await checkHpkeKeysMatch(aliceGroup, impl)
    await checkHpkeKeysMatch(bobGroup, impl)
    await checkHpkeKeysMatch(charlieGroup, impl)
    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}
