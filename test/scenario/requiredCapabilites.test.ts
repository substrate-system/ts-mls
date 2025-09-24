import { createGroup, joinGroup } from '../../src/clientState'
import { createCommit } from '../../src/createCommit'
import { emptyPskIndex } from '../../src/pskIndex'
import type { Credential } from '../../src/credential'
import type { CiphersuiteName } from '../../src/crypto/ciphersuite'
import { getCiphersuiteFromName, ciphersuites } from '../../src/crypto/ciphersuite'
import { getCiphersuiteImpl } from '../../src/crypto/getCiphersuiteImpl'
import { generateKeyPackage } from '../../src/keyPackage'
import type { ProposalAdd } from '../../src/proposal'
import { defaultLifetime } from '../../src/lifetime'
import type { Capabilities } from '../../src/capabilities'
import type { Extension } from '../../src/extension'
import type { RequiredCapabilities } from '../../src/requiredCapabilities'
import { encodeRequiredCapabilities } from '../../src/requiredCapabilities'
import { ValidationError } from '../../src/mlsError'

test.concurrent.each(Object.keys(ciphersuites))('Required Capabilities extension %s', async (cs) => {
    await requiredCapatabilitiesTest(cs as CiphersuiteName)
})

async function requiredCapatabilitiesTest (cipherSuite: CiphersuiteName) {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

    const requiredCapabilities: RequiredCapabilities = {
        extensionTypes: [7, 8],
        credentialTypes: ['x509', 'basic'],
        proposalTypes: [],
    }

    const capabilities: Capabilities = {
        extensions: [7, 8, 9],
        credentials: ['x509', 'basic'],
        proposals: [],
        versions: ['mls10'],
        ciphersuites: [cipherSuite],
    }

    const aliceCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('alice') }
    const alice = await generateKeyPackage(aliceCredential, capabilities, defaultLifetime, [], impl)

    const groupId = new TextEncoder().encode('group1')

    const requiredCapabilitiesExtension: Extension = {
        extensionType: 'required_capabilities',
        extensionData: encodeRequiredCapabilities(requiredCapabilities),
    }

    let aliceGroup = await createGroup(
        groupId,
        alice.publicPackage,
        alice.privatePackage,
        [requiredCapabilitiesExtension],
        impl,
    )

    const bobCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('bob') }
    const bob = await generateKeyPackage(bobCredential, capabilities, defaultLifetime, [], impl)

    const minimalCapabilites: Capabilities = {
        extensions: [],
        credentials: ['basic'],
        proposals: [],
        versions: ['mls10'],
        ciphersuites: [cipherSuite],
    }

    const charlieCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('charlie') }
    const charlie = await generateKeyPackage(charlieCredential, minimalCapabilites, defaultLifetime, [], impl)

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

    const addCharlieProposal: ProposalAdd = {
        proposalType: 'add',
        add: {
            keyPackage: charlie.publicPackage,
        },
    }

    await expect(
        createCommit(
            {
                state: aliceGroup,
                cipherSuite: impl,
            },
            {
                extraProposals: [addCharlieProposal],
            },
        ),
    ).rejects.toThrow(ValidationError)
}
