import { createGroup } from '../../src/clientState'
import { createGroupInfoWithExternalPub } from '../../src/createCommit'
import type { Credential } from '../../src/credential'
import type { CiphersuiteName } from '../../src/crypto/ciphersuite'
import { getCiphersuiteFromName, ciphersuites } from '../../src/crypto/ciphersuite'
import { getCiphersuiteImpl } from '../../src/crypto/getCiphersuiteImpl'
import { generateKeyPackage } from '../../src/keyPackage'
import { defaultLifetime } from '../../src/lifetime'
import type { Capabilities } from '../../src/capabilities'
import type { Extension, ExtensionType } from '../../src/extension'

test.concurrent.each(Object.keys(ciphersuites))('GroupInfo Custom Extensions %s', async (cs) => {
    await customExtensionTest(cs as CiphersuiteName)
})

async function customExtensionTest (cipherSuite: CiphersuiteName) {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

    const customExtensionType: ExtensionType = 7

    const capabilities: Capabilities = {
        extensions: [customExtensionType],
        credentials: ['basic'],
        proposals: [],
        versions: ['mls10'],
        ciphersuites: [cipherSuite],
    }

    const aliceCredential: Credential = { credentialType: 'basic', identity: new TextEncoder().encode('alice') }
    const alice = await generateKeyPackage(aliceCredential, capabilities, defaultLifetime, [], impl)

    const groupId = new TextEncoder().encode('group1')

    const aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

    const extensionData = new TextEncoder().encode('custom extension data')

    const customExtension: Extension = {
        extensionType: customExtensionType,
        extensionData,
    }

    const gi = await createGroupInfoWithExternalPub(aliceGroup, [customExtension], impl)

    expect(gi.extensions.find((e) => e.extensionType === customExtensionType)).toStrictEqual(customExtension)
}
