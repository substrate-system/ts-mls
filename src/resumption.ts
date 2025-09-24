import type { ClientState } from './clientState.js'
import { makePskIndex, createGroup, joinGroup } from './clientState.js'
import type { CreateCommitResult } from './createCommit.js'
import { createCommit } from './createCommit.js'
import type { CiphersuiteName, CiphersuiteImpl } from './crypto/ciphersuite.js'
import { getCiphersuiteFromName } from './crypto/ciphersuite.js'
import { getCiphersuiteImpl } from './crypto/getCiphersuiteImpl.js'
import { defaultCryptoProvider } from './crypto/implementation/default/provider.js'
import type { CryptoProvider } from './crypto/provider.js'
import type { Extension } from './extension.js'
import type { KeyPackage, PrivateKeyPackage } from './keyPackage.js'
import { UsageError } from './mlsError.js'
import type { ResumptionPSKUsageName, PreSharedKeyID } from './presharedkey.js'
import type { Proposal, ProposalAdd, ProposalPSK } from './proposal.js'
import type { ProtocolVersionName } from './protocolVersion.js'
import type { RatchetTree } from './ratchetTree.js'
import type { Welcome } from './welcome.js'

export async function reinitGroup (
    state: ClientState,
    groupId: Uint8Array,
    version: ProtocolVersionName,
    cipherSuite: CiphersuiteName,
    extensions: Extension[],
    cs: CiphersuiteImpl,
): Promise<CreateCommitResult> {
    const reinitProposal: Proposal = {
        proposalType: 'reinit',
        reinit: {
            groupId,
            version,
            cipherSuite,
            extensions,
        },
    }

    return createCommit(
        {
            state,
            pskIndex: makePskIndex(state, {}),
            cipherSuite: cs,
        },
        {
            extraProposals: [reinitProposal],
        },
    )
}

export async function reinitCreateNewGroup (
    state: ClientState,
    keyPackage: KeyPackage,
    privateKeyPackage: PrivateKeyPackage,
    memberKeyPackages: KeyPackage[],
    groupId: Uint8Array,
    cipherSuite: CiphersuiteName,
    extensions: Extension[],
    provider: CryptoProvider = defaultCryptoProvider,
): Promise<CreateCommitResult> {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite), provider)
    const newGroup = await createGroup(groupId, keyPackage, privateKeyPackage, extensions, cs)

    const addProposals: Proposal[] = memberKeyPackages.map((kp) => ({
        proposalType: 'add',
        add: { keyPackage: kp },
    }))

    const psk = makeResumptionPsk(state, 'reinit', cs)

    const resumptionPsk: Proposal = {
        proposalType: 'psk',
        psk: {
            preSharedKeyId: psk.id,
        },
    }

    return createCommit(
        {
            state: newGroup,
            pskIndex: makePskIndex(state, {}),
            cipherSuite: cs,
        },
        {
            extraProposals: [...addProposals, resumptionPsk],
        },
    )
}

export function makeResumptionPsk (
    state: ClientState,
    usage: ResumptionPSKUsageName,
    cs: CiphersuiteImpl,
): { id: PreSharedKeyID; secret: Uint8Array } {
    const secret = state.keySchedule.resumptionPsk

    const pskNonce = cs.rng.randomBytes(cs.kdf.size)

    const psk = {
        pskEpoch: state.groupContext.epoch,
        pskGroupId: state.groupContext.groupId,
        psktype: 'resumption',
        pskNonce,
        usage,
    } as const

    return { id: psk, secret }
}

export async function branchGroup (
    state: ClientState,
    keyPackage: KeyPackage,
    privateKeyPackage: PrivateKeyPackage,
    memberKeyPackages: KeyPackage[],
    newGroupId: Uint8Array,
    cs: CiphersuiteImpl,
): Promise<CreateCommitResult> {
    const resumptionPsk = makeResumptionPsk(state, 'branch', cs)

    const pskSearch = makePskIndex(state, {})

    const newGroup = await createGroup(newGroupId, keyPackage, privateKeyPackage, state.groupContext.extensions, cs)

    const addMemberProposals: ProposalAdd[] = memberKeyPackages.map((kp) => ({
        proposalType: 'add',
        add: {
            keyPackage: kp,
        },
    }))

    const branchPskProposal: ProposalPSK = {
        proposalType: 'psk',
        psk: {
            preSharedKeyId: resumptionPsk.id,
        },
    }

    return createCommit(
        {
            state: newGroup,
            pskIndex: pskSearch,
            cipherSuite: cs,
        },
        {
            extraProposals: [...addMemberProposals, branchPskProposal],
        },
    )
}

export async function joinGroupFromBranch (
    oldState: ClientState,
    welcome: Welcome,
    keyPackage: KeyPackage,
    privateKeyPackage: PrivateKeyPackage,
    ratchetTree: RatchetTree | undefined,
    cs: CiphersuiteImpl,
): Promise<ClientState> {
    const pskSearch = makePskIndex(oldState, {})

    return await joinGroup(welcome, keyPackage, privateKeyPackage, pskSearch, cs, ratchetTree, oldState)
}

export async function joinGroupFromReinit (
    suspendedState: ClientState,
    welcome: Welcome,
    keyPackage: KeyPackage,
    privateKeyPackage: PrivateKeyPackage,
    ratchetTree: RatchetTree | undefined,
    provider: CryptoProvider = defaultCryptoProvider,
): Promise<ClientState> {
    const pskSearch = makePskIndex(suspendedState, {})
    if (suspendedState.groupActiveState.kind !== 'suspendedPendingReinit') { throw new UsageError('Cannot reinit because no init proposal found in last commit') }

    const cs = await getCiphersuiteImpl(
        getCiphersuiteFromName(suspendedState.groupActiveState.reinit.cipherSuite),
        provider,
    )

    return await joinGroup(welcome, keyPackage, privateKeyPackage, pskSearch, cs, ratchetTree, suspendedState)
}
