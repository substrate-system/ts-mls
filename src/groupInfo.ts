import { decodeUint32, encodeUint32 } from './codec/number.js'
import type { Decoder } from './codec/tlsDecoder.js'
import { mapDecoders } from './codec/tlsDecoder.js'
import type { Encoder } from './codec/tlsEncoder.js'
import { contramapEncoders } from './codec/tlsEncoder.js'
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from './codec/variableLength.js'
import type { CiphersuiteImpl } from './crypto/ciphersuite.js'
import type { Kdf } from './crypto/kdf.js'
import { deriveSecret } from './crypto/kdf.js'
import type { Signature } from './crypto/signature.js'
import { signWithLabel, verifyWithLabel } from './crypto/signature.js'
import type { Extension } from './extension.js'
import { decodeExtension, encodeExtension } from './extension.js'
import type { GroupContext } from './groupContext.js'
import { decodeGroupContext, encodeGroupContext, extractEpochSecret } from './groupContext.js'
import { CodecError } from './mlsError.js'
import type { RatchetTree } from './ratchetTree.js'
import { decodeRatchetTree } from './ratchetTree.js'

export interface GroupInfoTBS {
  groupContext: GroupContext
  extensions: Extension[]
  confirmationTag: Uint8Array
  signer: number
}

export const encodeGroupInfoTBS: Encoder<GroupInfoTBS> = contramapEncoders(
    [encodeGroupContext, encodeVarLenType(encodeExtension), encodeVarLenData, encodeUint32],
    (g) => [g.groupContext, g.extensions, g.confirmationTag, g.signer] as const,
)

export const decodeGroupInfoTBS: Decoder<GroupInfoTBS> = mapDecoders(
    [decodeGroupContext, decodeVarLenType(decodeExtension), decodeVarLenData, decodeUint32],
    (groupContext, extensions, confirmationTag, signer) => ({
        groupContext,
        extensions,
        confirmationTag,
        signer,
    }),
)

export type GroupInfo = GroupInfoTBS & {
  signature: Uint8Array
}

export const encodeGroupInfo: Encoder<GroupInfo> = contramapEncoders(
    [encodeGroupInfoTBS, encodeVarLenData],
    (g) => [g, g.signature] as const,
)

export const decodeGroupInfo: Decoder<GroupInfo> = mapDecoders(
    [decodeGroupInfoTBS, decodeVarLenData],
    (tbs, signature) => ({
        ...tbs,
        signature,
    }),
)

export function ratchetTreeFromExtension (info: GroupInfo): RatchetTree | undefined {
    const treeExtension = info.extensions.find((ex) => ex.extensionType === 'ratchet_tree')

    if (treeExtension !== undefined) {
        const tree = decodeRatchetTree(treeExtension.extensionData, 0)
        if (tree === undefined) throw new CodecError('Could not decode RatchetTree')
        return tree[0]
    }
}

export async function signGroupInfo (tbs: GroupInfoTBS, privateKey: Uint8Array, s: Signature): Promise<GroupInfo> {
    const signature = await signWithLabel(privateKey, 'GroupInfoTBS', encodeGroupInfoTBS(tbs), s)
    return { ...tbs, signature }
}

export function verifyGroupInfoSignature (gi: GroupInfo, publicKey: Uint8Array, s: Signature): Promise<boolean> {
    return verifyWithLabel(publicKey, 'GroupInfoTBS', encodeGroupInfoTBS(gi), gi.signature, s)
}

export async function verifyGroupInfoConfirmationTag (
    gi: GroupInfo,
    joinerSecret: Uint8Array,
    pskSecret: Uint8Array,
    cs: CiphersuiteImpl,
): Promise<boolean> {
    const epochSecret = await extractEpochSecret(gi.groupContext, joinerSecret, cs.kdf, pskSecret)
    const key = await deriveSecret(epochSecret, 'confirm', cs.kdf)
    return cs.hash.verifyMac(key, gi.confirmationTag, gi.groupContext.confirmedTranscriptHash)
}

export async function extractWelcomeSecret (joinerSecret: Uint8Array, pskSecret: Uint8Array, kdf: Kdf) {
    return deriveSecret(await kdf.extract(joinerSecret, pskSecret), 'welcome', kdf)
}
