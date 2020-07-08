import { ethers } from 'ethers'
import didJWT from 'did-jwt'
import ThreeId from './3id'

const OWNER_PRIV_KEY = '0x58cf0ea0bfd990225d0e3c077f9ba302c79591c3fb11f11bc33df560fbe251a8'

class DidTestHelpers {
  constructor (ipfs) {
    if (!ipfs) throw new Error('Must helper class with an instance of ipfs')
    this.ipfs = ipfs
    this.provider = ethers.getDefaultProvider()
    this.signers = {}
    this._privateKeys = []
  }

  async generateAccounts (keys, length = 10) {
    const accounts = []

    const wallets = this.getWallets(keys, length)

    for (let i = 0; i < wallets.length; i++) {
      const wal = wallets[i]
      const id = await ThreeId.getIdFromEthAddress(wal.address, this.provider, this.ipfs, wal)
      const did = id._rootDID
      this.signers[did] = id.getSigner()
      accounts.push(did)
    }

    return accounts
  }

  async getOwner () {
    const owner = new ethers.Wallet(OWNER_PRIV_KEY)
    const id = await ThreeId.getIdFromEthAddress(owner.address, this.provider, this.ipfs, owner)
    const did = id._rootDID
    this.signers[did] = id.getSigner()
    return did
  }

  getPrivateKeys () {
    return this._privateKeys
  }

  getIPFS () {
    if (!this.ipfs) throw new Error('Must generate accounts before you can get the ipfs instance')
    return this.ipfs
  }

  async createJWTFromDID (did, payload) {
    if (!this.signers[did]) throw new Error(`DID '${did}' provided does not have signer`)

    const settings = {
      issuer: did,
      signer: this.signers[did]
    }

    return await didJWT.createJWT(payload, settings)
  }

  getSigners () {
    return this.signers
  }

  getWallets (keys, length) {
    const wallets = []

    if (keys) {
      this._privateKeys = keys
      this._privateKeys.forEach(async key => {
        const wal = new ethers.Wallet(key)
        wallets.push(wal)
      })
    } else {
      for (let i = 0; i < length; i++) {
        const wal = ethers.Wallet.createRandom()
        this._privateKeys.push(wal.privateKey)
        wallets.push(wal)
      }
    }

    return wallets
  }
}

export default DidTestHelpers
