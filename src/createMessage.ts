import type { ClientState } from './clientState.js'
import { checkCanSendApplicationMessages, processProposal } from './clientState.js'
import type { CiphersuiteImpl } from './crypto/ciphersuite.js'
import type { MLSMessage } from './message.js'
import type { PrivateMessage } from './privateMessage.js'
import { protectProposal, protectApplicationData } from './messageProtection.js'
import { protectProposalPublic } from './messageProtectionPublic.js'
import type { Proposal } from './proposal.js'
import { addUnappliedProposal } from './unappliedProposals.js'

export async function createProposal (
    state: ClientState,
    publicMessage: boolean,
    proposal: Proposal,
    cs: CiphersuiteImpl,
    authenticatedData: Uint8Array = new Uint8Array(),
): Promise<{ newState: ClientState; message: MLSMessage }> {
    if (publicMessage) {
        const result = await protectProposalPublic(
            state.signaturePrivateKey,
            state.keySchedule.membershipKey,
            state.groupContext,
            authenticatedData,
            proposal,
            state.privatePath.leafIndex,
            cs,
        )
        const newState = await processProposal(
            state,
            { content: result.publicMessage.content, auth: result.publicMessage.auth, wireformat: 'mls_public_message' },
            proposal,
            cs.hash,
        )
        return {
            newState,
            message: { wireformat: 'mls_public_message', version: 'mls10', publicMessage: result.publicMessage },
        }
    } else {
        const result = await protectProposal(
            state.signaturePrivateKey,
            state.keySchedule.senderDataSecret,
            proposal,
            authenticatedData,
            state.groupContext,
            state.secretTree,
            state.privatePath.leafIndex,
            state.clientConfig.paddingConfig,
            cs,
        )

        const newState = {
            ...state,
            secretTree: result.newSecretTree,
            unappliedProposals: addUnappliedProposal(
                result.proposalRef,
                state.unappliedProposals,
                proposal,
                state.privatePath.leafIndex,
            ),
        }

        return {
            newState,
            message: { wireformat: 'mls_private_message', version: 'mls10', privateMessage: result.privateMessage },
        }
    }
}

export async function createApplicationMessage (
    state: ClientState,
    message: Uint8Array,
    cs: CiphersuiteImpl,
    authenticatedData: Uint8Array = new Uint8Array(),
): Promise<{ newState: ClientState; privateMessage: PrivateMessage }> {
    checkCanSendApplicationMessages(state)

    const result = await protectApplicationData(
        state.signaturePrivateKey,
        state.keySchedule.senderDataSecret,
        message,
        authenticatedData,
        state.groupContext,
        state.secretTree,
        state.privatePath.leafIndex,
        state.clientConfig.paddingConfig,
        cs,
    )

    return { newState: { ...state, secretTree: result.newSecretTree }, privateMessage: result.privateMessage }
}
