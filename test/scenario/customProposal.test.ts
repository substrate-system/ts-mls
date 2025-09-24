import { createGroup, joinGroup } from '../../src/clientState'
import { createCommit } from '../../src/createCommit'
import { emptyPskIndex } from '../../src/pskIndex'
import type { Credential } from '../../src/credential'
import type { CiphersuiteName } from '../../src/crypto/ciphersuite'
import { getCiphersuiteFromName, ciphersuites } from '../../src/crypto/ciphersuite'
import { getCiphersuiteImpl } from '../../src/crypto/getCiphersuiteImpl'
import { generateKeyPackage } from '../../src/keyPackage'
import type { Proposal, ProposalAdd } from '../../src/proposal'
import { testEveryoneCanMessageEveryone } from './common.js'
import { defaultLifetime } from '../../src/lifetime'
import type { Capabilities } from '../../src/capabilities'
import { createApplicationMessage, createProposal, processPrivateMessage } from '../../src'
import { UsageError } from '../../src/mlsError'

test.concurrent.each(Object.keys(ciphersuites))('Custom Proposals %s', async (cs) => {
    await customProposalTest(cs as CiphersuiteName)
})

async function customProposalTest (cipherSuite: CiphersuiteName) {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

    const customProposalType: number = 8

    const capabilities: Capabilities = {
        extensions: [],
        credentials: ['basic'],
        proposals: [customProposalType],
        versions: ['mls10'],
        ciphersuites: [cipherSuite],
    }

    const aliceCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('alice') }
    const alice = await generateKeyPackage(aliceCredential, capabilities, defaultLifetime, [], impl)

    const groupId = new TextEncoder().encode('group1')

    let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

    const bobCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('bob') }
    const bob = await generateKeyPackage(bobCredential, capabilities, defaultLifetime, [], impl)

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
        { extraProposals: [addBobProposal] },
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

    const proposalData = new TextEncoder().encode('custom proposal data')

    const customProposal: Proposal = {
        proposalType: 8,
        proposalData,
    }

    const createProposalResult = await createProposal(bobGroup, false, customProposal, impl)

    bobGroup = createProposalResult.newState

    if (createProposalResult.message.wireformat !== 'mls_private_message') throw new Error('Expected private message')

    const processProposalResult = await processPrivateMessage(
        aliceGroup,
        createProposalResult.message.privateMessage,
        emptyPskIndex,
        impl,
        (p) => {
            if (p.kind !== 'proposal') throw new Error('Expected proposal')
            expect(p.proposal.proposal).toStrictEqual(customProposal)
            return 'accept'
        },
    )

    aliceGroup = processProposalResult.newState

    // creating an application message will fail now
    await expect(createApplicationMessage(aliceGroup, new Uint8Array([1, 2, 3]), impl)).rejects.toThrow(UsageError)

    const createCommitResult = await createCommit({
        state: aliceGroup,

        cipherSuite: impl,
    })

    aliceGroup = createCommitResult.newState

    if (createCommitResult.commit.wireformat !== 'mls_private_message') throw new Error('Expected private message')

    const processCommitResult = await processPrivateMessage(
        bobGroup,
        createCommitResult.commit.privateMessage,
        emptyPskIndex,
        impl,
        (p) => {
            if (p.kind !== 'commit') throw new Error('Expected commit')
            expect(p.proposals.map((p) => p.proposal)).toStrictEqual([customProposal])
            return 'accept'
        },
    )

    bobGroup = processCommitResult.newState

    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
