import { decodeUint64, encodeUint64 } from './codec/number.js'
import type { Decoder } from './codec/tlsDecoder.js'
import { mapDecoders } from './codec/tlsDecoder.js'
import type { Encoder } from './codec/tlsEncoder.js'
import { contramapEncoders } from './codec/tlsEncoder.js'
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from './codec/variableLength.js'
import type { CiphersuiteName } from './crypto/ciphersuite.js'
import { decodeCiphersuite, encodeCiphersuite } from './crypto/ciphersuite.js'

import type { Kdf } from './crypto/kdf.js'
import { expandWithLabel } from './crypto/kdf.js'
import type { Extension } from './extension.js'
import { decodeExtension, encodeExtension } from './extension.js'

import type { ProtocolVersionName } from './protocolVersion.js'
import { decodeProtocolVersion, encodeProtocolVersion } from './protocolVersion.js'

export interface GroupContext {
  version: ProtocolVersionName
  cipherSuite: CiphersuiteName
  groupId: Uint8Array
  epoch: bigint
  treeHash: Uint8Array
  confirmedTranscriptHash: Uint8Array
  extensions: Extension[]
}

export const encodeGroupContext: Encoder<GroupContext> = contramapEncoders(
    [
        encodeProtocolVersion,
        encodeCiphersuite,
        encodeVarLenData, // groupId
        encodeUint64, // epoch
        encodeVarLenData, // treeHash
        encodeVarLenData, // confirmedTranscriptHash
        encodeVarLenType(encodeExtension),
    ],
    (gc) =>
    [gc.version, gc.cipherSuite, gc.groupId, gc.epoch, gc.treeHash, gc.confirmedTranscriptHash, gc.extensions] as const,
)

export const decodeGroupContext: Decoder<GroupContext> = mapDecoders(
    [
        decodeProtocolVersion,
        decodeCiphersuite,
        decodeVarLenData, // groupId
        decodeUint64, // epoch
        decodeVarLenData, // treeHash
        decodeVarLenData, // confirmedTranscriptHash
        decodeVarLenType(decodeExtension),
    ],
    (version, cipherSuite, groupId, epoch, treeHash, confirmedTranscriptHash, extensions) => ({
        version,
        cipherSuite,
        groupId,
        epoch,
        treeHash,
        confirmedTranscriptHash,
        extensions,
    }),
)

export async function extractEpochSecret (
    context: GroupContext,
    joinerSecret: Uint8Array,
    kdf: Kdf,
    pskSecret?: Uint8Array,
) {
    const psk = pskSecret === undefined ? new Uint8Array(kdf.size) : pskSecret
    const extracted = await kdf.extract(joinerSecret, psk)

    return expandWithLabel(extracted, 'epoch', encodeGroupContext(context), kdf.size, kdf)
}

export async function extractJoinerSecret (
    context: GroupContext,
    previousInitSecret: Uint8Array,
    commitSecret: Uint8Array,
    kdf: Kdf,
) {
    const extracted = await kdf.extract(previousInitSecret, commitSecret)

    return expandWithLabel(extracted, 'joiner', encodeGroupContext(context), kdf.size, kdf)
}
