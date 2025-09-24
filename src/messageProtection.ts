import type { AuthenticatedContent } from './authenticatedContent.js'
import { makeProposalRef } from './authenticatedContent.js'
import type { CiphersuiteImpl } from './crypto/ciphersuite.js'
import type { FramedContentTBSApplicationOrProposal } from './framedContent.js'
import {
    signFramedContentApplicationOrProposal,
    verifyFramedContentSignature,
} from './framedContent.js'
import type { GroupContext } from './groupContext.js'
import type { Proposal } from './proposal.js'
import type {
    PrivateContentAAD,
    PrivateMessage,
    PrivateMessageContent
} from './privateMessage.js'
import {
    decodePrivateMessageContent,
    decryptSenderData,
    encodePrivateContentAAD,
    encodePrivateMessageContent,
    encryptSenderData,
    toAuthenticatedContent,
} from './privateMessage.js'
import type { SecretTree } from './secretTree.js'
import { consumeRatchet, ratchetToGeneration } from './secretTree.js'
import type { RatchetTree } from './ratchetTree.js'
import { getSignaturePublicKeyFromLeafIndex } from './ratchetTree.js'
import type { SenderData, SenderDataAAD } from './sender.js'
import { leafToNodeIndex, toLeafIndex } from './treemath.js'
import type { KeyRetentionConfig } from './keyRetentionConfig.js'
import type { MlsError } from './mlsError.js'
import { CryptoVerificationError, CodecError, ValidationError, InternalError } from './mlsError.js'
import type { PaddingConfig } from './paddingConfig.js'

export interface ProtectApplicationDataResult {
  privateMessage: PrivateMessage
  newSecretTree: SecretTree
}

export async function protectApplicationData (
    signKey: Uint8Array,
    senderDataSecret: Uint8Array,
    applicationData: Uint8Array,
    authenticatedData: Uint8Array,
    groupContext: GroupContext,
    secretTree: SecretTree,
    leafIndex: number,
    paddingConfig: PaddingConfig,
    cs: CiphersuiteImpl,
): Promise<ProtectApplicationDataResult> {
    const tbs: FramedContentTBSApplicationOrProposal = {
        protocolVersion: groupContext.version,
        wireformat: 'mls_private_message',
        content: {
            contentType: 'application',
            applicationData,
            groupId: groupContext.groupId,
            epoch: groupContext.epoch,
            sender: {
                senderType: 'member',
                leafIndex,
            },
            authenticatedData,
        },
        senderType: 'member',
        context: groupContext,
    }

    const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)

    const content = {
        ...tbs.content,
        auth,
    }

    const result = await protect(
        senderDataSecret,
        authenticatedData,
        groupContext,
        secretTree,
        content,
        leafIndex,
        paddingConfig,
        cs,
    )

    return { newSecretTree: result.tree, privateMessage: result.privateMessage }
}

export interface ProtectProposalResult {
  privateMessage: PrivateMessage
  newSecretTree: SecretTree
  proposalRef: Uint8Array
}

export async function protectProposal (
    signKey: Uint8Array,
    senderDataSecret: Uint8Array,
    p: Proposal,
    authenticatedData: Uint8Array,
    groupContext: GroupContext,
    secretTree: SecretTree,
    leafIndex: number,
    paddingConfig: PaddingConfig,
    cs: CiphersuiteImpl,
): Promise<ProtectProposalResult> {
    const tbs = {
        protocolVersion: groupContext.version,
        wireformat: 'mls_private_message' as const,
        content: {
            contentType: 'proposal' as const,
            proposal: p,
            groupId: groupContext.groupId,
            epoch: groupContext.epoch,
            sender: {
                senderType: 'member' as const,
                leafIndex,
            },
            authenticatedData,
        },
        senderType: 'member' as const,
        context: groupContext,
    }

    const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)
    const content = { ...tbs.content, auth }

    const privateMessage = await protect(
        senderDataSecret,
        authenticatedData,
        groupContext,
        secretTree,
        content,
        leafIndex,
        paddingConfig,
        cs,
    )

    const newSecretTree = privateMessage.tree

    const authenticatedContent = {
        wireformat: 'mls_private_message' as const,
        content,
        auth,
    }
    const proposalRef = await makeProposalRef(authenticatedContent, cs.hash)

    return { privateMessage: privateMessage.privateMessage, newSecretTree, proposalRef }
}

export interface ProtectResult {
  privateMessage: PrivateMessage
  tree: SecretTree
}

export async function protect (
    senderDataSecret: Uint8Array,
    authenticatedData: Uint8Array,
    groupContext: GroupContext,
    secretTree: SecretTree,
    content: PrivateMessageContent,
    leafIndex: number,
    config: PaddingConfig,
    cs: CiphersuiteImpl,
): Promise<{ privateMessage: PrivateMessage; tree: SecretTree }> {
    const node = secretTree[leafToNodeIndex(toLeafIndex(leafIndex))]
    if (node === undefined) throw new InternalError('Bad node index for secret tree')

    const { newTree, generation, reuseGuard, nonce, key } = await consumeRatchet(
        secretTree,
        leafToNodeIndex(toLeafIndex(leafIndex)),
        content.contentType,
        cs,
    )

    const aad: PrivateContentAAD = {
        groupId: groupContext.groupId,
        epoch: groupContext.epoch,
        contentType: content.contentType,
        authenticatedData,
    }

    const ciphertext = await cs.hpke.encryptAead(
        key,
        nonce,
        encodePrivateContentAAD(aad),
        encodePrivateMessageContent(config)(content),
    )

    const senderData: SenderData = {
        leafIndex,
        generation,
        reuseGuard,
    }

    const senderAad: SenderDataAAD = {
        groupId: groupContext.groupId,
        epoch: groupContext.epoch,
        contentType: content.contentType,
    }

    const encryptedSenderData = await encryptSenderData(senderDataSecret, senderData, senderAad, ciphertext, cs)

    return {
        privateMessage: {
            groupId: groupContext.groupId,
            epoch: groupContext.epoch,
            encryptedSenderData,
            contentType: content.contentType,
            authenticatedData,
            ciphertext,
        },
        tree: newTree,
    }
}

export interface UnprotectResult {
  content: AuthenticatedContent
  tree: SecretTree
}

export async function unprotectPrivateMessage (
    senderDataSecret: Uint8Array,
    msg: PrivateMessage,
    secretTree: SecretTree,
    ratchetTree: RatchetTree,
    groupContext: GroupContext,
    config: KeyRetentionConfig,
    cs: CiphersuiteImpl,
    overrideSignatureKey?: Uint8Array,
): Promise<UnprotectResult> {
    const senderData = await decryptSenderData(msg, senderDataSecret, cs)

    if (senderData === undefined) throw new CodecError('Could not decode senderdata')

    validateSenderData(senderData, ratchetTree)

    const { key, nonce, newTree } = await ratchetToGeneration(secretTree, senderData, msg.contentType, config, cs)

    const aad: PrivateContentAAD = {
        groupId: msg.groupId,
        epoch: msg.epoch,
        contentType: msg.contentType,
        authenticatedData: msg.authenticatedData,
    }

    const decrypted = await cs.hpke.decryptAead(key, nonce, encodePrivateContentAAD(aad), msg.ciphertext)

    const pmc = decodePrivateMessageContent(msg.contentType)(decrypted, 0)?.[0]

    if (pmc === undefined) throw new CodecError('Could not decode PrivateMessageContent')

    const content = toAuthenticatedContent(pmc, msg, senderData.leafIndex)

    const signaturePublicKey =
    overrideSignatureKey !== undefined
        ? overrideSignatureKey
        : getSignaturePublicKeyFromLeafIndex(ratchetTree, toLeafIndex(senderData.leafIndex))

    const signatureValid = await verifyFramedContentSignature(
        signaturePublicKey,
        'mls_private_message',
        content.content,
        content.auth,
        groupContext,
        cs.signature,
    )

    if (!signatureValid) throw new CryptoVerificationError('Signature invalid')

    return { tree: newTree, content }
}

export function validateSenderData (senderData: SenderData, tree: RatchetTree): MlsError | undefined {
    if (tree[leafToNodeIndex(toLeafIndex(senderData.leafIndex))]?.nodeType !== 'leaf') { return new ValidationError('SenderData did not point to a non-blank leaf node') }
}
