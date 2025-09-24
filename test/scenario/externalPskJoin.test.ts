import { createGroup, joinGroup, makePskIndex } from '../../src/clientState'
import { createCommit } from '../../src/createCommit'
import type { Credential } from '../../src/credential'
import type { CiphersuiteName } from '../../src/crypto/ciphersuite'
import { ciphersuites, getCiphersuiteFromName } from '../../src/crypto/ciphersuite'
import { getCiphersuiteImpl } from '../../src/crypto/getCiphersuiteImpl'
import { generateKeyPackage } from '../../src/keyPackage'
import type { Proposal, ProposalAdd } from '../../src/proposal'
import { bytesToBase64 } from '../../src/util/byteArray'
import { checkHpkeKeysMatch } from '../crypto/keyMatch'
import { testEveryoneCanMessageEveryone } from './common.js'
import { defaultLifetime } from '../../src/lifetime'
import { defaultCapabilities } from '../../src/defaultCapabilities'

test.concurrent.each(Object.keys(ciphersuites))('External PSK Join %s', async (cs) => {
    await externalPskJoin(cs as CiphersuiteName)
})

async function externalPskJoin (cipherSuite: CiphersuiteName) {
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

    const pskSecret = impl.rng.randomBytes(impl.kdf.size)
    const pskNonce = impl.rng.randomBytes(impl.kdf.size)

    const pskId = new TextEncoder().encode('psk-1')

    const pskProposal: Proposal = {
        proposalType: 'psk',
        psk: {
            preSharedKeyId: {
                psktype: 'external',
                pskId,
                pskNonce,
            },
        },
    }

    const base64PskId = bytesToBase64(pskId)

    const sharedPsks = { [base64PskId]: pskSecret }

    const commitResult = await createCommit(
        {
            state: aliceGroup,
            pskIndex: makePskIndex(aliceGroup, sharedPsks),
            cipherSuite: impl,
        },
        {
            extraProposals: [addBobProposal, pskProposal],
        },
    )

    aliceGroup = commitResult.newState

    const bobGroup = await joinGroup(
    commitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    makePskIndex(undefined, sharedPsks),
    impl,
    aliceGroup.ratchetTree,
    )

    await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
    await checkHpkeKeysMatch(aliceGroup, impl)
    await checkHpkeKeysMatch(bobGroup, impl)
}
