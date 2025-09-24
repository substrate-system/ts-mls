import type { Decoder } from './codec/tlsDecoder.js'
import { mapDecoders } from './codec/tlsDecoder.js'
import type { Encoder } from './codec/tlsEncoder.js'
import { contramapEncoders } from './codec/tlsEncoder.js'
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from './codec/variableLength.js'
import type { CiphersuiteImpl, CiphersuiteName } from './crypto/ciphersuite.js'
import { decodeCiphersuite, encodeCiphersuite } from './crypto/ciphersuite.js'
import type { PublicKey, Hpke, PrivateKey } from './crypto/hpke.js'
import { encryptWithLabel, decryptWithLabel } from './crypto/hpke.js'
import { expandWithLabel } from './crypto/kdf.js'
import type { GroupInfo } from './groupInfo.js'
import { decodeGroupInfo, encodeGroupInfo, extractWelcomeSecret } from './groupInfo.js'
import type { GroupSecrets } from './groupSecrets.js'
import { decodeGroupSecrets, encodeGroupSecrets } from './groupSecrets.js'
import type { HPKECiphertext } from './hpkeCiphertext.js'
import { encodeHpkeCiphertext, decodeHpkeCiphertext } from './hpkeCiphertext.js'
import { ValidationError } from './mlsError.js'
import { constantTimeEqual } from './util/constantTimeCompare.js'

export interface EncryptedGroupSecrets {
  newMember: Uint8Array
  encryptedGroupSecrets: HPKECiphertext
}

export const encodeEncryptedGroupSecrets: Encoder<EncryptedGroupSecrets> = contramapEncoders(
    [encodeVarLenData, encodeHpkeCiphertext],
    (egs) => [egs.newMember, egs.encryptedGroupSecrets] as const,
)

export const decodeEncryptedGroupSecrets: Decoder<EncryptedGroupSecrets> = mapDecoders(
    [decodeVarLenData, decodeHpkeCiphertext],
    (newMember, encryptedGroupSecrets) => ({ newMember, encryptedGroupSecrets }),
)

export interface Welcome {
  cipherSuite: CiphersuiteName
  secrets: EncryptedGroupSecrets[]
  encryptedGroupInfo: Uint8Array
}

export const encodeWelcome: Encoder<Welcome> = contramapEncoders(
    [encodeCiphersuite, encodeVarLenType(encodeEncryptedGroupSecrets), encodeVarLenData],
    (welcome) => [welcome.cipherSuite, welcome.secrets, welcome.encryptedGroupInfo] as const,
)

export const decodeWelcome: Decoder<Welcome> = mapDecoders(
    [decodeCiphersuite, decodeVarLenType(decodeEncryptedGroupSecrets), decodeVarLenData],
    (cipherSuite, secrets, encryptedGroupInfo) => ({ cipherSuite, secrets, encryptedGroupInfo }),
)

export function welcomeNonce (welcomeSecret: Uint8Array, cs: CiphersuiteImpl) {
    return expandWithLabel(welcomeSecret, 'nonce', new Uint8Array(), cs.hpke.nonceLength, cs.kdf)
}

export function welcomeKey (welcomeSecret: Uint8Array, cs: CiphersuiteImpl) {
    return expandWithLabel(welcomeSecret, 'key', new Uint8Array(), cs.hpke.keyLength, cs.kdf)
}

export async function encryptGroupInfo (
    groupInfo: GroupInfo,
    welcomeSecret: Uint8Array,
    cs: CiphersuiteImpl,
): Promise<Uint8Array> {
    const key = await welcomeKey(welcomeSecret, cs)
    const nonce = await welcomeNonce(welcomeSecret, cs)
    const encrypted = await cs.hpke.encryptAead(key, nonce, undefined, encodeGroupInfo(groupInfo))

    return encrypted
}

export async function decryptGroupInfo (
    w: Welcome,
    joinerSecret: Uint8Array,
    pskSecret: Uint8Array,
    cs: CiphersuiteImpl,
): Promise<GroupInfo | undefined> {
    const welcomeSecret = await extractWelcomeSecret(joinerSecret, pskSecret, cs.kdf)

    const key = await welcomeKey(welcomeSecret, cs)
    const nonce = await welcomeNonce(welcomeSecret, cs)
    const decrypted = await cs.hpke.decryptAead(key, nonce, undefined, w.encryptedGroupInfo)

    const decoded = decodeGroupInfo(decrypted, 0)
    return decoded?.[0]
}

export function encryptGroupSecrets (
    initKey: PublicKey,
    encryptedGroupInfo: Uint8Array,
    groupSecrets: GroupSecrets,
    hpke: Hpke,
) {
    return encryptWithLabel(initKey, 'Welcome', encryptedGroupInfo, encodeGroupSecrets(groupSecrets), hpke)
}

export async function decryptGroupSecrets (
    initPrivateKey: PrivateKey,
    keyPackageRef: Uint8Array,
    welcome: Welcome,
    hpke: Hpke,
): Promise<GroupSecrets | undefined> {
    const secret = welcome.secrets.find((s) => constantTimeEqual(s.newMember, keyPackageRef))
    if (secret === undefined) throw new ValidationError('No matching secret found')
    const decrypted = await decryptWithLabel(
        initPrivateKey,
        'Welcome',
        welcome.encryptedGroupInfo,
        secret.encryptedGroupSecrets.kemOutput,
        secret.encryptedGroupSecrets.ciphertext,
        hpke,
    )
    return decodeGroupSecrets(decrypted, 0)?.[0]
}
