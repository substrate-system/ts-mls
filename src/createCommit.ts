import type {
    ClientState,
    ApplyProposalsResult,
    GroupActiveState
} from './clientState.js'
import {
    addHistoricalReceiverData, makePskIndex, throwIfDefined, validateRatchetTree,
    applyProposals,
    nextEpochContext,
    exportSecret,
    checkCanSendHandshakeMessages
} from './clientState.js'
import type { AuthenticatedContentCommit } from './authenticatedContent.js'
import type { CiphersuiteImpl } from './crypto/ciphersuite.js'
import { decryptWithLabel } from './crypto/hpke.js'
import { deriveSecret } from './crypto/kdf.js'
import type {
    FramedContentAuthDataCommit,
    FramedContentCommit
} from './framedContent.js'
import {
    createContentCommitSignature,
    createConfirmationTag
} from './framedContent.js'
import type { GroupContext } from './groupContext.js'
import { encodeGroupContext } from './groupContext.js'
import type {
    GroupInfo,
    GroupInfoTBS
} from './groupInfo.js'
import {
    ratchetTreeFromExtension,
    signGroupInfo,
    verifyGroupInfoSignature,
} from './groupInfo.js'
import type { KeyPackage, PrivateKeyPackage } from './keyPackage.js'
import { makeKeyPackageRef } from './keyPackage.js'
import type { EpochSecrets } from './keySchedule.js'
import { initializeEpoch } from './keySchedule.js'
import type { MLSMessage } from './message.js'
import { protect } from './messageProtection.js'
import { protectPublicMessage } from './messageProtectionPublic.js'
import { pathToPathSecrets } from './pathSecrets.js'
import type { PrivateKeyPath } from './privateKeyPath.js'
import { mergePrivateKeyPaths, updateLeafKey, toPrivateKeyPath } from './privateKeyPath.js'
import type { Proposal, ProposalExternalInit } from './proposal.js'
import type { ProposalOrRef } from './proposalOrRefType.js'
import type { PskIndex } from './pskIndex.js'
import type { RatchetTree } from './ratchetTree.js'
import {
    addLeafNode,
    encodeRatchetTree,
    getCredentialFromLeafIndex,
    getSignaturePublicKeyFromLeafIndex,
    removeLeafNode,
} from './ratchetTree.js'
import type { SecretTree } from './secretTree.js'
import { createSecretTree } from './secretTree.js'
import { treeHashRoot } from './treeHash.js'
import type { LeafIndex, NodeIndex } from './treemath.js'
import { leafWidth, nodeToLeafIndex, toLeafIndex, toNodeIndex } from './treemath.js'
import type { PathSecret, UpdatePath } from './updatePath.js'
import { createUpdatePath, firstCommonAncestor, firstMatchAncestor } from './updatePath.js'
import { base64ToBytes } from './util/byteArray.js'
import type { Welcome, EncryptedGroupSecrets } from './welcome.js'
import { encryptGroupInfo, encryptGroupSecrets } from './welcome.js'
import { CryptoVerificationError, InternalError, UsageError, ValidationError } from './mlsError.js'
import type { ClientConfig } from './clientConfig.js'
import { defaultClientConfig } from './clientConfig.js'
import type { Extension } from './extension.js'
import { extensionsSupportedByCapabilities } from './extension.js'

export interface MLSContext {
  state: ClientState
  cipherSuite: CiphersuiteImpl
  pskIndex?: PskIndex
}

export interface CreateCommitResult {
  newState: ClientState
  welcome: Welcome | undefined
  commit: MLSMessage
}

export interface CreateCommitOptions {
  wireAsPublicMessage?: boolean
  extraProposals?: Proposal[]
  ratchetTreeExtension?: boolean
  groupInfoExtensions?: Extension[]
  authenticatedData?: Uint8Array
}

export async function createCommit (context: MLSContext, options?: CreateCommitOptions): Promise<CreateCommitResult> {
    const { state, pskIndex = makePskIndex(state, {}), cipherSuite } = context
    const {
        wireAsPublicMessage = false,
        extraProposals = [],
        ratchetTreeExtension = false,
        authenticatedData = new Uint8Array(),
        groupInfoExtensions = [],
    } = options ?? {}

    checkCanSendHandshakeMessages(state)

    const wireformat = wireAsPublicMessage ? 'mls_public_message' : 'mls_private_message'

    const allProposals = bundleAllProposals(state, extraProposals)

    const res = await applyProposals(
        state,
        allProposals,
        toLeafIndex(state.privatePath.leafIndex),
        pskIndex,
        true,
        cipherSuite,
    )

    if (res.additionalResult.kind === 'externalCommit') throw new UsageError('Cannot create externalCommit as a member')

    const suspendedPendingReinit = res.additionalResult.kind === 'reinit' ? res.additionalResult.reinit : undefined

    const [tree, updatePath, pathSecrets, newPrivateKey] = res.needsUpdatePath
        ? await createUpdatePath(
            res.tree,
            toLeafIndex(state.privatePath.leafIndex),
            state.groupContext,
            state.signaturePrivateKey,
            cipherSuite,
        )
        : [res.tree, undefined, [] as PathSecret[], undefined]

    const updatedExtensions =
    res.additionalResult.kind === 'memberCommit' && res.additionalResult.extensions.length > 0
        ? res.additionalResult.extensions
        : state.groupContext.extensions

    const groupContextWithExtensions = { ...state.groupContext, extensions: updatedExtensions }

    const privateKeys = mergePrivateKeyPaths(
        newPrivateKey !== undefined
            ? updateLeafKey(state.privatePath, await cipherSuite.hpke.exportPrivateKey(newPrivateKey))
            : state.privatePath,
        await toPrivateKeyPath(pathToPathSecrets(pathSecrets), state.privatePath.leafIndex, cipherSuite),
    )

    const lastPathSecret = pathSecrets.at(-1)

    const commitSecret =
    lastPathSecret === undefined
        ? new Uint8Array(cipherSuite.kdf.size)
        : await deriveSecret(lastPathSecret.secret, 'path', cipherSuite.kdf)

    const { signature, framedContent } = await createContentCommitSignature(
        state.groupContext,
        wireformat,
        { proposals: allProposals, path: updatePath },
        { senderType: 'member', leafIndex: state.privatePath.leafIndex },
        authenticatedData,
        state.signaturePrivateKey,
        cipherSuite.signature,
    )

    const treeHash = await treeHashRoot(tree, cipherSuite.hash)

    const updatedGroupContext = await nextEpochContext(
        groupContextWithExtensions,
        wireformat,
        framedContent,
        signature,
        treeHash,
        state.confirmationTag,
        cipherSuite.hash,
    )

    const epochSecrets = await initializeEpoch(
        state.keySchedule.initSecret,
        commitSecret,
        updatedGroupContext,
        res.pskSecret,
        cipherSuite.kdf,
    )

    const confirmationTag = await createConfirmationTag(
        epochSecrets.keySchedule.confirmationKey,
        updatedGroupContext.confirmedTranscriptHash,
        cipherSuite.hash,
    )

    const authData: FramedContentAuthDataCommit = {
        contentType: framedContent.contentType,
        signature,
        confirmationTag,
    }

    const [commit] = await protectCommit(
        wireAsPublicMessage,
        state,
        authenticatedData,
        framedContent,
        authData,
        cipherSuite,
    )

    const welcome: Welcome | undefined = await createWelcome(
        ratchetTreeExtension,
        updatedGroupContext,
        confirmationTag,
        state,
        tree,
        cipherSuite,
        epochSecrets,
        res,
        pathSecrets,
        groupInfoExtensions,
    )

    const groupActiveState: GroupActiveState = res.selfRemoved
        ? { kind: 'removedFromGroup' }
        : suspendedPendingReinit !== undefined
            ? { kind: 'suspendedPendingReinit', reinit: suspendedPendingReinit }
            : { kind: 'active' }

    const newState: ClientState = {
        groupContext: updatedGroupContext,
        ratchetTree: tree,
        secretTree: await createSecretTree(
            leafWidth(tree.length),
            epochSecrets.keySchedule.encryptionSecret,
            cipherSuite.kdf,
        ),
        keySchedule: epochSecrets.keySchedule,
        privatePath: privateKeys,
        unappliedProposals: {},
        historicalReceiverData: addHistoricalReceiverData(state),
        confirmationTag,
        signaturePrivateKey: state.signaturePrivateKey,
        groupActiveState,
        clientConfig: state.clientConfig,
    }

    return { newState, welcome, commit }
}

function bundleAllProposals (state: ClientState, extraProposals: Proposal[]): ProposalOrRef[] {
    const refs: ProposalOrRef[] = Object.keys(state.unappliedProposals).map((p) => ({
        proposalOrRefType: 'reference',
        reference: base64ToBytes(p),
    }))

    const proposals: ProposalOrRef[] = extraProposals.map((p) => ({ proposalOrRefType: 'proposal', proposal: p }))

    return [...refs, ...proposals]
}

async function createWelcome (
    ratchetTreeExtension: boolean,
    groupContext: GroupContext,
    confirmationTag: Uint8Array,
    state: ClientState,
    tree: RatchetTree,
    cs: CiphersuiteImpl,
    epochSecrets: EpochSecrets,
    res: ApplyProposalsResult,
    pathSecrets: PathSecret[],
    extensions: Extension[],
): Promise<Welcome | undefined> {
    const groupInfo = ratchetTreeExtension
        ? await createGroupInfoWithRatchetTree(groupContext, confirmationTag, state, tree, extensions, cs)
        : await createGroupInfo(groupContext, confirmationTag, state, extensions, cs)

    const encryptedGroupInfo = await encryptGroupInfo(groupInfo, epochSecrets.welcomeSecret, cs)

    const encryptedGroupSecrets: EncryptedGroupSecrets[] =
    res.additionalResult.kind === 'memberCommit'
        ? await Promise.all(
            res.additionalResult.addedLeafNodes.map(([leafNodeIndex, keyPackage]) => {
                return createEncryptedGroupSecrets(
                    tree,
                    leafNodeIndex,
                    state,
                    pathSecrets,
                    cs,
                    keyPackage,
                    encryptedGroupInfo,
                    epochSecrets,
                    res,
                )
            }),
        )
        : []

    return encryptedGroupSecrets.length > 0
        ? {
            cipherSuite: groupContext.cipherSuite,
            secrets: encryptedGroupSecrets,
            encryptedGroupInfo,
        }
        : undefined
}

async function createEncryptedGroupSecrets (
    tree: RatchetTree,
    leafNodeIndex: LeafIndex,
    state: ClientState,
    pathSecrets: PathSecret[],
    cs: CiphersuiteImpl,
    keyPackage: KeyPackage,
    encryptedGroupInfo: Uint8Array,
    epochSecrets: EpochSecrets,
    res: ApplyProposalsResult,
) {
    const nodeIndex = firstCommonAncestor(tree, leafNodeIndex, toLeafIndex(state.privatePath.leafIndex))
    const pathSecret = pathSecrets.find((ps) => ps.nodeIndex === nodeIndex)
    const pk = await cs.hpke.importPublicKey(keyPackage.initKey)
    const egs = await encryptGroupSecrets(
        pk,
        encryptedGroupInfo,
        { joinerSecret: epochSecrets.joinerSecret, pathSecret: pathSecret?.secret, psks: res.pskIds },
        cs.hpke,
    )

    const ref = await makeKeyPackageRef(keyPackage, cs.hash)

    return { newMember: ref, encryptedGroupSecrets: { kemOutput: egs.enc, ciphertext: egs.ct } }
}

export async function createGroupInfo (
    groupContext: GroupContext,
    confirmationTag: Uint8Array,
    state: ClientState,
    extensions: Extension[],
    cs: CiphersuiteImpl,
): Promise<GroupInfo> {
    const groupInfoTbs: GroupInfoTBS = {
        groupContext,
        extensions,
        confirmationTag,
        signer: state.privatePath.leafIndex,
    }

    return signGroupInfo(groupInfoTbs, state.signaturePrivateKey, cs.signature)
}

export async function createGroupInfoWithRatchetTree (
    groupContext: GroupContext,
    confirmationTag: Uint8Array,
    state: ClientState,
    tree: RatchetTree,
    extensions: Extension[],
    cs: CiphersuiteImpl,
): Promise<GroupInfo> {
    const encodedTree = encodeRatchetTree(tree)

    const gi = await createGroupInfo(
        groupContext,
        confirmationTag,
        state,
        [...extensions, { extensionType: 'ratchet_tree', extensionData: encodedTree }],
        cs,
    )

    return gi
}

export async function createGroupInfoWithExternalPub (
    state: ClientState,
    extensions: Extension[],
    cs: CiphersuiteImpl,
): Promise<GroupInfo> {
    const externalKeyPair = await cs.hpke.deriveKeyPair(state.keySchedule.externalSecret)
    const externalPub = await cs.hpke.exportPublicKey(externalKeyPair.publicKey)

    const gi = await createGroupInfo(
        state.groupContext,
        state.confirmationTag,
        state,
        [...extensions, { extensionType: 'external_pub', extensionData: externalPub }],
        cs,
    )

    return gi
}

export async function createGroupInfoWithExternalPubAndRatchetTree (
    state: ClientState,
    extensions: Extension[],
    cs: CiphersuiteImpl,
): Promise<GroupInfo> {
    const encodedTree = encodeRatchetTree(state.ratchetTree)

    const externalKeyPair = await cs.hpke.deriveKeyPair(state.keySchedule.externalSecret)
    const externalPub = await cs.hpke.exportPublicKey(externalKeyPair.publicKey)

    const gi = await createGroupInfo(
        state.groupContext,
        state.confirmationTag,
        state,
        [
            ...extensions,
            { extensionType: 'external_pub', extensionData: externalPub },
            { extensionType: 'ratchet_tree', extensionData: encodedTree },
        ],
        cs,
    )

    return gi
}

async function protectCommit (
    publicMessage: boolean,
    state: ClientState,
    authenticatedData: Uint8Array,
    content: FramedContentCommit,
    authData: FramedContentAuthDataCommit,
    cs: CiphersuiteImpl,
): Promise<[MLSMessage, SecretTree]> {
    const wireformat = publicMessage ? 'mls_public_message' : 'mls_private_message'

    const authenticatedContent: AuthenticatedContentCommit = {
        wireformat,
        content,
        auth: authData,
    }

    if (publicMessage) {
        const msg = await protectPublicMessage(
            state.keySchedule.membershipKey,
            state.groupContext,
            authenticatedContent,
            cs,
        )

        return [{ version: 'mls10', wireformat: 'mls_public_message', publicMessage: msg }, state.secretTree]
    } else {
        const res = await protect(
            state.keySchedule.senderDataSecret,
            authenticatedData,
            state.groupContext,
            state.secretTree,
            { ...content, auth: authData },
            state.privatePath.leafIndex,
            state.clientConfig.paddingConfig,
            cs,
        )

        return [{ version: 'mls10', wireformat: 'mls_private_message', privateMessage: res.privateMessage }, res.tree]
    }
}

export async function applyUpdatePathSecret (
    tree: RatchetTree,
    privatePath: PrivateKeyPath,
    senderLeafIndex: LeafIndex,
    gc: GroupContext,
    path: UpdatePath,
    excludeNodes: NodeIndex[],
    cs: CiphersuiteImpl,
): Promise<{ nodeIndex: NodeIndex; pathSecret: Uint8Array }> {
    const {
        nodeIndex: ancestorNodeIndex,
        resolution,
        updateNode,
    } = firstMatchAncestor(tree, toLeafIndex(privatePath.leafIndex), senderLeafIndex, path)

    for (const [i, nodeIndex] of filterNewLeaves(resolution, excludeNodes).entries()) {
        if (privatePath.privateKeys[nodeIndex] !== undefined) {
            const key = await cs.hpke.importPrivateKey(privatePath.privateKeys[nodeIndex])
            const ct = updateNode!.encryptedPathSecret[i]!

            const pathSecret = await decryptWithLabel(
                key,
                'UpdatePathNode',
                encodeGroupContext(gc),
                ct.kemOutput,
                ct.ciphertext,
                cs.hpke,
            )
            return { nodeIndex: ancestorNodeIndex, pathSecret }
        }
    }

    throw new InternalError('No overlap between provided private keys and update path')
}

export async function joinGroupExternal (
    groupInfo: GroupInfo,
    keyPackage: KeyPackage,
    privateKeys: PrivateKeyPackage,
    resync: boolean,
    cs: CiphersuiteImpl,
    tree?: RatchetTree,
    clientConfig: ClientConfig = defaultClientConfig,
    authenticatedData: Uint8Array = new Uint8Array(),
) {
    const externalPub = groupInfo.extensions.find((ex) => ex.extensionType === 'external_pub')

    if (externalPub === undefined) throw new UsageError('Could not find external_pub extension')

    const allExtensionsSupported = extensionsSupportedByCapabilities(
        groupInfo.groupContext.extensions,
        keyPackage.leafNode.capabilities,
    )
    if (!allExtensionsSupported) throw new UsageError('client does not support every extension in the GroupContext')

    const { enc, secret: initSecret } = await exportSecret(externalPub.extensionData, cs)

    const ratchetTree = ratchetTreeFromExtension(groupInfo) ?? tree

    if (ratchetTree === undefined) throw new UsageError('No RatchetTree passed and no ratchet_tree extension')

    throwIfDefined(
        await validateRatchetTree(
            ratchetTree,
            groupInfo.groupContext,
            clientConfig.lifetimeConfig,
            clientConfig.authService,
            groupInfo.groupContext.treeHash,
            cs,
        ),
    )

    const signaturePublicKey = getSignaturePublicKeyFromLeafIndex(ratchetTree, toLeafIndex(groupInfo.signer))

    const signerCredential = getCredentialFromLeafIndex(ratchetTree, toLeafIndex(groupInfo.signer))

    const credentialVerified = await clientConfig.authService.validateCredential(signerCredential, signaturePublicKey)

    if (!credentialVerified) throw new ValidationError('Could not validate credential')

    const groupInfoSignatureVerified = await verifyGroupInfoSignature(groupInfo, signaturePublicKey, cs.signature)

    if (!groupInfoSignatureVerified) throw new CryptoVerificationError('Could not verify groupInfo Signature')

    const formerLeafIndex = resync
        ? nodeToLeafIndex(
            toNodeIndex(
                ratchetTree.findIndex((n) => {
                    if (n !== undefined && n.nodeType === 'leaf') {
                        return clientConfig.keyPackageEqualityConfig.compareKeyPackageToLeafNode(keyPackage, n.leaf)
                    }
                    return false
                }),
            ),
        )
        : undefined

    const updatedTree = formerLeafIndex !== undefined ? removeLeafNode(ratchetTree, formerLeafIndex) : ratchetTree

    const [treeWithNewLeafNode, newLeafNodeIndex] = addLeafNode(updatedTree, keyPackage.leafNode)

    const [newTree, updatePath, pathSecrets, newPrivateKey] = await createUpdatePath(
        treeWithNewLeafNode,
        nodeToLeafIndex(newLeafNodeIndex),
        groupInfo.groupContext,
        privateKeys.signaturePrivateKey,
        cs,
    )

    const privateKeyPath = updateLeafKey(
        await toPrivateKeyPath(pathToPathSecrets(pathSecrets), nodeToLeafIndex(newLeafNodeIndex), cs),
        await cs.hpke.exportPrivateKey(newPrivateKey),
    )

    const lastPathSecret = pathSecrets.at(-1)

    const commitSecret =
    lastPathSecret === undefined
        ? new Uint8Array(cs.kdf.size)
        : await deriveSecret(lastPathSecret.secret, 'path', cs.kdf)

    const externalInitProposal: ProposalExternalInit = {
        proposalType: 'external_init',
        externalInit: { kemOutput: enc },
    }
    const proposals: Proposal[] =
    formerLeafIndex !== undefined
        ? [{ proposalType: 'remove', remove: { removed: formerLeafIndex } }, externalInitProposal]
        : [externalInitProposal]

    const pskSecret = new Uint8Array(cs.kdf.size)

    const { signature, framedContent } = await createContentCommitSignature(
        groupInfo.groupContext,
        'mls_public_message',
        { proposals: proposals.map((p) => ({ proposalOrRefType: 'proposal', proposal: p })), path: updatePath },
        {
            senderType: 'new_member_commit',
        },
        authenticatedData,
        privateKeys.signaturePrivateKey,
        cs.signature,
    )

    const treeHash = await treeHashRoot(newTree, cs.hash)

    const groupContext = await nextEpochContext(
        groupInfo.groupContext,
        'mls_public_message',
        framedContent,
        signature,
        treeHash,
        groupInfo.confirmationTag,
        cs.hash,
    )

    const epochSecrets = await initializeEpoch(initSecret, commitSecret, groupContext, pskSecret, cs.kdf)

    const confirmationTag = await createConfirmationTag(
        epochSecrets.keySchedule.confirmationKey,
        groupContext.confirmedTranscriptHash,
        cs.hash,
    )

    const state: ClientState = {
        ratchetTree: newTree,
        groupContext,
        secretTree: await createSecretTree(leafWidth(newTree.length), epochSecrets.keySchedule.encryptionSecret, cs.kdf),
        privatePath: privateKeyPath,
        confirmationTag,
        historicalReceiverData: new Map(),
        signaturePrivateKey: privateKeys.signaturePrivateKey,
        keySchedule: epochSecrets.keySchedule,
        unappliedProposals: {},
        groupActiveState: { kind: 'active' },
        clientConfig,
    }

    const authenticatedContent: AuthenticatedContentCommit = {
        content: framedContent,
        auth: { signature, confirmationTag, contentType: 'commit' },
        wireformat: 'mls_public_message',
    }

    const msg = await protectPublicMessage(epochSecrets.keySchedule.membershipKey, groupContext, authenticatedContent, cs)

    return { publicMessage: msg, newState: state }
}
export function filterNewLeaves (resolution: NodeIndex[], excludeNodes: NodeIndex[]): NodeIndex[] {
    const set = new Set(excludeNodes)
    return resolution.filter((i) => !set.has(i))
}
