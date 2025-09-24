import type { Proposal } from './proposal.js'
import { bytesToBase64 } from './util/byteArray.js'

export interface ProposalWithSender {
  proposal: Proposal
  senderLeafIndex: number | undefined
}
export type UnappliedProposals = Record<string, ProposalWithSender>
export function addUnappliedProposal (
    ref: Uint8Array,
    proposals: UnappliedProposals,
    proposal: Proposal,
    senderLeafIndex: number | undefined,
): UnappliedProposals {
    const r = bytesToBase64(ref)
    return {
        ...proposals,
        [r]: { proposal, senderLeafIndex },
    }
}
