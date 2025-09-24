import type {
    AuthenticatedContent,
    AuthenticatedContentProposalOrCommit,
    AuthenticatedContentTBM
} from './authenticatedContent.js'
import {
    createMembershipTag,
    verifyMembershipTag,
} from './authenticatedContent.js'
import type { CiphersuiteImpl } from './crypto/ciphersuite.js'
import type { FramedContent } from './framedContent.js'
import {
    signFramedContentApplicationOrProposal,
    toTbs,
    verifyFramedContentSignature,
} from './framedContent.js'
import type { GroupContext } from './groupContext.js'
import { CryptoVerificationError, UsageError } from './mlsError.js'
import type { Proposal } from './proposal.js'
import type { ExternalPublicMessage, PublicMessage } from './publicMessage.js'
import { findSignaturePublicKey } from './publicMessage.js'
import type { RatchetTree } from './ratchetTree.js'
import type { SenderNonMember } from './sender.js'

export interface ProtectProposalPublicResult {
  publicMessage: PublicMessage
}

export async function protectProposalPublic (
    signKey: Uint8Array,
    membershipKey: Uint8Array,
    groupContext: GroupContext,
    authenticatedData: Uint8Array,
    proposal: Proposal,
    leafIndex: number,
    cs: CiphersuiteImpl,
): Promise<ProtectProposalPublicResult> {
    const framedContent: FramedContent = {
        groupId: groupContext.groupId,
        epoch: groupContext.epoch,
        sender: { senderType: 'member', leafIndex },
        contentType: 'proposal',
        authenticatedData,
        proposal,
    }

    const tbs = {
        protocolVersion: groupContext.version,
        wireformat: 'mls_public_message',
        content: framedContent,
        senderType: 'member',
        context: groupContext,
    } as const

    const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)

    const authenticatedContent: AuthenticatedContent = {
        wireformat: 'mls_public_message',
        content: framedContent,
        auth,
    }

    const msg = await protectPublicMessage(membershipKey, groupContext, authenticatedContent, cs)

    return { publicMessage: msg }
}

export async function protectExternalProposalPublic (
    signKey: Uint8Array,
    groupContext: GroupContext,
    authenticatedData: Uint8Array,
    proposal: Proposal,
    sender: SenderNonMember,
    cs: CiphersuiteImpl,
): Promise<ProtectProposalPublicResult> {
    const framedContent: FramedContent = {
        groupId: groupContext.groupId,
        epoch: groupContext.epoch,
        sender,
        contentType: 'proposal',
        authenticatedData,
        proposal,
    }

    const tbs = {
        protocolVersion: groupContext.version,
        wireformat: 'mls_public_message',
        content: framedContent,
        senderType: sender.senderType,
        context: groupContext,
    } as const

    const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)

    const msg: ExternalPublicMessage = {
        content: framedContent,
        auth,
        senderType: sender.senderType,
    }

    return { publicMessage: msg }
}

export async function protectPublicMessage (
    membershipKey: Uint8Array,
    groupContext: GroupContext,
    content: AuthenticatedContent,
    cs: CiphersuiteImpl,
): Promise<PublicMessage> {
    if (content.content.contentType === 'application') throw new UsageError("Can't make an application message public")

    if (content.content.sender.senderType == 'member') {
        const authenticatedContent: AuthenticatedContentTBM = {
            contentTbs: toTbs(content.content, 'mls_public_message', groupContext),
            auth: content.auth,
        }

        const tag = await createMembershipTag(membershipKey, authenticatedContent, cs.hash)
        return {
            content: content.content,
            auth: content.auth,
            senderType: 'member',
            membershipTag: tag,
        }
    }

    return {
        content: content.content,
        auth: content.auth,
        senderType: content.content.sender.senderType,
    }
}

export interface ProtectCommitPublicResult {
  publicMessage: PublicMessage
}

export async function unprotectPublicMessage (
    membershipKey: Uint8Array,
    groupContext: GroupContext,
    ratchetTree: RatchetTree,
    msg: PublicMessage,
    cs: CiphersuiteImpl,
    overrideSignatureKey?: Uint8Array,
): Promise<AuthenticatedContentProposalOrCommit> {
    if (msg.content.contentType === 'application') throw new UsageError("Can't make an application message public")

    if (msg.senderType === 'member') {
        const authenticatedContent: AuthenticatedContentTBM = {
            contentTbs: toTbs(msg.content, 'mls_public_message', groupContext),
            auth: msg.auth,
        }

        if (!(await verifyMembershipTag(membershipKey, authenticatedContent, msg.membershipTag, cs.hash))) { throw new CryptoVerificationError('Could not verify membership') }
    }

    const signaturePublicKey =
    overrideSignatureKey !== undefined
        ? overrideSignatureKey
        : findSignaturePublicKey(ratchetTree, groupContext, msg.content)

    const signatureValid = await verifyFramedContentSignature(
        signaturePublicKey,
        'mls_public_message',
        msg.content,
        msg.auth,
        groupContext,
        cs.signature,
    )

    if (!signatureValid) throw new CryptoVerificationError('Signature invalid')

    return {
        wireformat: 'mls_public_message',
        content: msg.content,
        auth: msg.auth,
    }
}
