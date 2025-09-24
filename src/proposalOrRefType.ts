import { decodeUint8, encodeUint8 } from './codec/number.js'
import type { Decoder } from './codec/tlsDecoder.js'
import { flatMapDecoder, mapDecoder, mapDecoderOption } from './codec/tlsDecoder.js'
import type { Encoder } from './codec/tlsEncoder.js'
import { contramapEncoder, contramapEncoders } from './codec/tlsEncoder.js'
import { decodeVarLenData, encodeVarLenData } from './codec/variableLength.js'
import type { Proposal } from './proposal.js'
import { decodeProposal, encodeProposal } from './proposal.js'
import { enumNumberToKey } from './util/enumHelpers.js'

const proposalOrRefTypes = {
    proposal: 1,
    reference: 2,
} as const

export type ProposalOrRefTypeName = keyof typeof proposalOrRefTypes
export type ProposalOrRefTypeValue = (typeof proposalOrRefTypes)[ProposalOrRefTypeName]

export const encodeProposalOrRefType: Encoder<ProposalOrRefTypeName> = contramapEncoder(
    encodeUint8,
    (t) => proposalOrRefTypes[t],
)

export const decodeProposalOrRefType: Decoder<ProposalOrRefTypeName> = mapDecoderOption(
    decodeUint8,
    enumNumberToKey(proposalOrRefTypes),
)

export interface ProposalOrRefProposal {
  proposalOrRefType: 'proposal'
  proposal: Proposal
}
export interface ProposalOrRefProposalRef {
  proposalOrRefType: 'reference'
  reference: Uint8Array
}

export type ProposalOrRef = ProposalOrRefProposal | ProposalOrRefProposalRef

export const encodeProposalOrRefProposal: Encoder<ProposalOrRefProposal> = contramapEncoders(
    [encodeProposalOrRefType, encodeProposal],
    (p) => [p.proposalOrRefType, p.proposal] as const,
)

export const encodeProposalOrRefProposalRef: Encoder<ProposalOrRefProposalRef> = contramapEncoders(
    [encodeProposalOrRefType, encodeVarLenData],
    (r) => [r.proposalOrRefType, r.reference] as const,
)

export const encodeProposalOrRef: Encoder<ProposalOrRef> = (input) => {
    switch (input.proposalOrRefType) {
        case 'proposal':
            return encodeProposalOrRefProposal(input)
        case 'reference':
            return encodeProposalOrRefProposalRef(input)
    }
}

export const decodeProposalOrRef: Decoder<ProposalOrRef> = flatMapDecoder(
    decodeProposalOrRefType,
    (proposalOrRefType): Decoder<ProposalOrRef> => {
        switch (proposalOrRefType) {
            case 'proposal':
                return mapDecoder(decodeProposal, (proposal) => ({ proposalOrRefType, proposal }))
            case 'reference':
                return mapDecoder(decodeVarLenData, (reference) => ({ proposalOrRefType, reference }))
        }
    },
)
