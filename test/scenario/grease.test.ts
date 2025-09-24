import { createGroup, joinGroup } from '../../src/clientState'
import { createCommit } from '../../src/createCommit'
import { emptyPskIndex } from '../../src/pskIndex'
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
import { defaultGreaseConfig, greaseExtensions } from '../../src/grease'
import type { Capabilities } from '../../src/capabilities'
import { extensionTypeToNumber } from '../../src/extension'

test.concurrent.each(Object.keys(ciphersuites))('Grease %s', async (cs) => {
    await greaseTest(cs as CiphersuiteName)
})

async function greaseTest (cipherSuite: CiphersuiteName) {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

    const aliceCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('alice') }
    const greased = greaseExtensions(defaultGreaseConfig)
    const caps: Capabilities = {
        ...defaultCapabilities(),
        extensions: greased.map((n) => extensionTypeToNumber(n.extensionType)),
    }
    const alice = await generateKeyPackage(aliceCredential, caps, defaultLifetime, greased, impl)

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
        },
    )

    aliceGroup = addBobCommitResult.newState

    const bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
    )

    expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

    await checkHpkeKeysMatch(aliceGroup, impl)
    await checkHpkeKeysMatch(bobGroup, impl)
    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
