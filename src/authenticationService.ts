import type { Credential } from './credential.js'

export interface AuthenticationService {
  validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<boolean>
}

export const defaultAuthenticationService = {
    async validateCredential (_credential: Credential, _signaturePublicKey: Uint8Array): Promise<boolean> {
        return true
    },
}
