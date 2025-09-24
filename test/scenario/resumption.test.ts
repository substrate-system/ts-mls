import { createGroup, joinGroup } from '../../src/clientState'
import { createCommit } from '../../src/createCommit'
import { emptyPskIndex } from '../../src/pskIndex'
import { branchGroup, joinGroupFromBranch } from '../../src/resumption'
import type { Credential } from '../../src/credential'
import type { CiphersuiteName } from '../../src/crypto/ciphersuite'
import { ciphersuites, getCiphersuiteFromName } from '../../src/crypto/ciphersuite'
import { getCiphersuiteImpl } from '../../src/crypto/getCiphersuiteImpl'
import { generateKeyPackage } from '../../src/keyPackage'
import type { ProposalAdd } from '../../src/proposal'
import { checkHpkeKeysMatch } from '../crypto/keyMatch'
import { testEveryoneCanMessageEveryone } from './common.js'
import { defaultLifetime } from '../../src/lifetime'
import { defaultCapabilities } from '../../src/defaultCapabilities'

test.concurrent.each(Object.keys(ciphersuites))('Resumption %s', async (cs) => {
    await resumption(cs as CiphersuiteName)
})

async function resumption (cipherSuite: CiphersuiteName) {
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

    const commitResult = await createCommit(
        {
            state: aliceGroup,
            cipherSuite: impl,
        },
        {
            extraProposals: [addBobProposal],
        },
    )

    aliceGroup = commitResult.newState

    let bobGroup = await joinGroup(
    commitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
    )

    const bobNewKeyPackage = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

    const aliceNewKeyPackage = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

    const newGroupId = new TextEncoder().encode('new-group1')

    const branchCommitResult = await branchGroup(
        aliceGroup,
        aliceNewKeyPackage.publicPackage,
        aliceNewKeyPackage.privatePackage,
        [bobNewKeyPackage.publicPackage],
        newGroupId,
        impl,
    )

    aliceGroup = branchCommitResult.newState

    bobGroup = await joinGroupFromBranch(
        bobGroup,
    branchCommitResult.welcome!,
    bobNewKeyPackage.publicPackage,
    bobNewKeyPackage.privatePackage,
    aliceGroup.ratchetTree,
    impl,
    )

    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
    await checkHpkeKeysMatch(aliceGroup, impl)
    await checkHpkeKeysMatch(bobGroup, impl)
}
