import type { Decoder } from './codec/tlsDecoder.js'
import { flatMapDecoder, mapDecoder, mapDecoders } from './codec/tlsDecoder.js'
import type { Encoder } from './codec/tlsEncoder.js'
import { contramapEncoders } from './codec/tlsEncoder.js'
import type { Hash } from './crypto/hash.js'
import { refhash } from './crypto/hash.js'
import type {
    FramedContent,
    FramedContentApplicationData,
    FramedContentAuthData,
    FramedContentCommitData,
    FramedContentData,
    FramedContentProposalData,
    FramedContentTBS
} from './framedContent.js'
import {
    decodeFramedContent,
    decodeFramedContentAuthData,
    encodeFramedContent,
    encodeFramedContentAuthData,
    encodeFramedContentTBS
} from './framedContent.js'
import type { WireformatName } from './wireformat.js'
import { decodeWireformat, encodeWireformat } from './wireformat.js'

export interface AuthenticatedContent {
  wireformat: WireformatName
  content: FramedContent
  auth: FramedContentAuthData
}

export type AuthenticatedContentApplication = AuthenticatedContent & {
  content: FramedContentApplicationData & FramedContentData
}

export type AuthenticatedContentCommit = AuthenticatedContent & {
  content: FramedContentCommitData & FramedContentData
}

export type AuthenticatedContentProposal = AuthenticatedContent & {
  content: FramedContentProposalData & FramedContentData
}

export type AuthenticatedContentProposalOrCommit = AuthenticatedContent & {
  content: (FramedContentProposalData | FramedContentCommitData) & FramedContentData
}
export const encodeAuthenticatedContent: Encoder<AuthenticatedContent> = contramapEncoders(
    [encodeWireformat, encodeFramedContent, encodeFramedContentAuthData],
    (a) => [a.wireformat, a.content, a.auth] as const,
)

export const decodeAuthenticatedContent: Decoder<AuthenticatedContent> = mapDecoders(
    [
        decodeWireformat,
        flatMapDecoder(decodeFramedContent, (content) => {
            return mapDecoder(decodeFramedContentAuthData(content.contentType), (auth) => ({ content, auth }))
        }),
    ],
    (wireformat, contentAuth) => ({
        wireformat,
        ...contentAuth,
    }),
)

export interface AuthenticatedContentTBM {
  contentTbs: FramedContentTBS
  auth: FramedContentAuthData
}

export const encodeAuthenticatedContentTBM: Encoder<AuthenticatedContentTBM> = contramapEncoders(
    [encodeFramedContentTBS, encodeFramedContentAuthData],
    (t) => [t.contentTbs, t.auth] as const,
)

export function createMembershipTag (
    membershipKey: Uint8Array,
    tbm: AuthenticatedContentTBM,
    h: Hash,
): Promise<Uint8Array> {
    return h.mac(membershipKey, encodeAuthenticatedContentTBM(tbm))
}

export function verifyMembershipTag (
    membershipKey: Uint8Array,
    tbm: AuthenticatedContentTBM,
    tag: Uint8Array,
    h: Hash,
): Promise<boolean> {
    return h.verifyMac(membershipKey, tag, encodeAuthenticatedContentTBM(tbm))
}

export function makeProposalRef (proposal: AuthenticatedContent, h: Hash): Promise<Uint8Array> {
    return refhash('MLS 1.0 Proposal Reference', encodeAuthenticatedContent(proposal), h)
}
