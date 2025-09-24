import type { Decoder } from './codec/tlsDecoder.js'
import { flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from './codec/tlsDecoder.js'
import type { Encoder } from './codec/tlsEncoder.js'
import { contramapEncoders } from './codec/tlsEncoder.js'
import { decodeVarLenData, encodeVarLenData } from './codec/variableLength.js'
import type { Extension } from './extension.js'
import type { ExternalSender } from './externalSender.js'
import { decodeExternalSender } from './externalSender.js'
import type {
    FramedContent,
    FramedContentAuthData
} from './framedContent.js'
import {
    decodeFramedContent,
    decodeFramedContentAuthData,
    encodeFramedContent,
    encodeFramedContentAuthData
} from './framedContent.js'
import type { GroupContext } from './groupContext.js'
import { CodecError, ValidationError } from './mlsError.js'
import type { RatchetTree } from './ratchetTree.js'
import { getSignaturePublicKeyFromLeafIndex } from './ratchetTree.js'
import type { SenderTypeName } from './sender.js'
import { toLeafIndex } from './treemath.js'

type PublicMessageInfo = PublicMessageInfoMember | PublicMessageInfoMemberOther
type PublicMessageInfoMember = { senderType: 'member'; membershipTag: Uint8Array }
type PublicMessageInfoMemberOther = { senderType: Exclude<SenderTypeName, 'member'> }

export const encodePublicMessageInfo: Encoder<PublicMessageInfo> = (info) => {
    switch (info.senderType) {
        case 'member':
            return encodeVarLenData(info.membershipTag)
        case 'external':
        case 'new_member_proposal':
        case 'new_member_commit':
            return new Uint8Array()
    }
}

export function decodePublicMessageInfo (senderType: SenderTypeName): Decoder<PublicMessageInfo> {
    switch (senderType) {
        case 'member':
            return mapDecoder(decodeVarLenData, (membershipTag) => ({
                senderType,
                membershipTag,
            }))
        case 'external':
        case 'new_member_proposal':
        case 'new_member_commit':
            return succeedDecoder({ senderType })
    }
}

export type PublicMessage = { content: FramedContent; auth: FramedContentAuthData } & PublicMessageInfo
export type MemberPublicMessage = PublicMessage & PublicMessageInfoMember
export type ExternalPublicMessage = PublicMessage & PublicMessageInfoMemberOther

export const encodePublicMessage: Encoder<PublicMessage> = contramapEncoders(
    [encodeFramedContent, encodeFramedContentAuthData, encodePublicMessageInfo],
    (msg) => [msg.content, msg.auth, msg] as const,
)

export const decodePublicMessage: Decoder<PublicMessage> = flatMapDecoder(decodeFramedContent, (content) =>
    mapDecoders(
        [decodeFramedContentAuthData(content.contentType), decodePublicMessageInfo(content.sender.senderType)],
        (auth, info) => ({
            ...info,
            content,
            auth,
        }),
    ),
)

export function findSignaturePublicKey (
    ratchetTree: RatchetTree,
    groupContext: GroupContext,
    framedContent: FramedContent,
): Uint8Array {
    switch (framedContent.sender.senderType) {
        case 'member':
            return getSignaturePublicKeyFromLeafIndex(ratchetTree, toLeafIndex(framedContent.sender.leafIndex))
        case 'external': {
            const sender = senderFromExtension(groupContext.extensions, framedContent.sender.senderIndex)
            if (sender === undefined) throw new ValidationError('Received external but no external_sender extension')
            return sender.signaturePublicKey
        }
        case 'new_member_proposal':
            if (framedContent.contentType !== 'proposal') { throw new ValidationError('Received new_member_proposal but contentType is not proposal') }
            if (framedContent.proposal.proposalType !== 'add') { throw new ValidationError('Received new_member_proposal but proposalType was not add') }

            return framedContent.proposal.add.keyPackage.leafNode.signaturePublicKey
        case 'new_member_commit': {
            if (framedContent.contentType !== 'commit') { throw new ValidationError('Received new_member_commit but contentType is not commit') }

            if (framedContent.commit.path === undefined) throw new ValidationError('Commit contains no update path')
            return framedContent.commit.path.leafNode.signaturePublicKey
        }
    }
}

export function senderFromExtension (extensions: Extension[], senderIndex: number): ExternalSender | undefined {
    const externalSenderExtensions = extensions.filter((ex) => ex.extensionType === 'external_senders')

    const externalSenderExtension = externalSenderExtensions[senderIndex]

    if (externalSenderExtension !== undefined) {
        const externalSender = decodeExternalSender(externalSenderExtension.extensionData, 0)
        if (externalSender === undefined) throw new CodecError('Could not decode ExternalSender')

        return externalSender[0]
    }
}
