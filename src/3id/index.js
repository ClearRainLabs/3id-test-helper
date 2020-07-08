const { mnemonicToSeed, entropyToMnemonic } = require('@ethersproject/hdnode')
const EventEmitter = require('events')
const didJWT = require('did-jwt')
const { Resolver } = require('did-resolver')
const get3IdResolver = require('3id-resolver').getResolver
const DidDocument = require('ipfs-did-document')
const localstorage = require('store')
const Keyring = require('./keyring')
const nacl = require('tweetnacl')
const { randomNonce }  = require('./utils')
const sha256 = require('js-sha256').sha256

const DID_METHOD_NAME = '3'
const STORAGE_KEY = 'serialized3id_'
const POLL_INTERVAL = 500

class ThreeId {
  constructor (provider, ipfs, opts = {}) {
    this.events = new EventEmitter()
    this._provider = provider
    this._has3idProv = Boolean(opts.has3idProv)
    this._ipfs = ipfs
    this._pubkeys = { spaces: {} }
    const threeIdResolver = get3IdResolver(ipfs, { pin: true })
    const resolver = new Resolver({...threeIdResolver})
  }

  getSigningKey () {
    return this._keyringBySpace().getSigningKey()
  }

  getSigner () {
    return this._keyringBySpace().getJWTSigner()
  }

  async signJWT (payload, { space, expiresIn } = {}) {
    let issuer = this.DID
    if (space) {
      issuer = this._subDIDs[space]
    }

    const keyring = this._keyringBySpace(space)
    const settings = {
      signer: keyring.getJWTSigner(),
      issuer,
      expiresIn
    }
    return didJWT.createJWT(payload, settings)
  }

  get DID () {
    return this._rootDID
  }

  get muportDID () {
    return this._muportDID
  }

  getSubDID (space) {
    return this._subDIDs[space]
  }

  serializeState () {
    if (this._has3idProv) throw new Error('Can not serializeState of IdentityWallet')
    let stateObj = {
      managementAddress: this.managementAddress,
      seed: this._mainKeyring.serialize(),
      spaceSeeds: {},
    }
    Object.keys(this._keyrings).map(name => {
      stateObj.spaceSeeds[name] = this._keyrings[name].serialize()
    })
    return JSON.stringify(stateObj)
  }

  _initKeys (serializedState) {
    if (this._has3idProv) throw new Error('Can not initKeys of IdentityWallet')
    this._keyrings = {}
    const state = JSON.parse(serializedState)
    // TODO remove toLowerCase() in future, should be sanitized elsewhere
    //      this forces existing state to correct state so that address <->
    //      rootstore relation holds
    this.managementAddress = state.managementAddress.toLowerCase()
    this._mainKeyring = new Keyring(state.seed)
    Object.keys(state.spaceSeeds).map(name => {
      this._keyrings[name] = new Keyring(state.spaceSeeds[name])
    })
    localstorage.set(STORAGE_KEY + this.managementAddress, this.serializeState())
  }

  async _initDID () {
    this._rootDID = await this._init3ID()
    let spaces
    spaces = Object.keys(this._keyrings)

    const subDIDs = await Promise.all(
      spaces.map(space => {
        return this._init3ID(space)
      })
    )
    this._subDIDs = {}
    spaces.map((space, i) => {
      this._subDIDs[space] = subDIDs[i]
    })
  }

  async _init3ID (spaceName) {
    const doc = new DidDocument(this._ipfs, DID_METHOD_NAME)
    const pubkeys = await this.getPublicKeys(spaceName, true)
    if (!spaceName) {
      doc.addPublicKey('signingKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', pubkeys.signingKey)
      doc.addPublicKey('encryptionKey', 'Curve25519EncryptionPublicKey', 'publicKeyBase64', pubkeys.asymEncryptionKey)
      doc.addPublicKey('managementKey', 'Secp256k1VerificationKey2018', 'ethereumAddress', pubkeys.managementKey)
      doc.addAuthentication('Secp256k1SignatureAuthentication2018', 'signingKey')
    } else {
      doc.addPublicKey('subSigningKey', 'Secp256k1VerificationKey2018', 'publicKeyHex', pubkeys.signingKey)
      doc.addPublicKey('subEncryptionKey', 'Curve25519EncryptionPublicKey', 'publicKeyBase64', pubkeys.asymEncryptionKey)
      doc.addAuthentication('Secp256k1SignatureAuthentication2018', 'subSigningKey')
      doc.addCustomProperty('space', spaceName)
      doc.addCustomProperty('root', this.DID)
      const payload = {
        iat: null,
        subSigningKey: pubkeys.signingKey,
        subEncryptionKey: pubkeys.asymEncryptionKey,
        space: spaceName
      }
      const signature = (await this.signJWT(payload, { use3ID: true })).split('.')[2]
      doc.addCustomProperty('proof', { alg: 'ES256K', signature })
    }
    await doc.commit({ noTimestamp: true })
    return doc.DID
  }

  async getAddress () {
    return this.managementAddress
  }

  async authenticate (spaces, opts = {}) {
    spaces = spaces || []
    for (const space of spaces) {
      await this._initKeyringByName(space, wallet)
    }
  }

  async isAuthenticated (spaces = []) {
    return spaces.reduce((acc, space) => acc && Object.keys(this._subDIDs).includes(space), true)
  }

  async _initKeyringByName (name, wallet) {
    if (this._has3idProv) throw new Error('Can not initKeyringByName of IdentityWallet')
    if (!this._keyrings[name]) {
      const text = `Allow this app to open your ${name} space.`
      var msg = '0x' + Buffer.from(text, 'utf8').toString('hex')
      const sig = await wallet.signMessage(msg)
      const entropy = '0x' + sha256(sig.slice(2))
      const seed = mnemonicToSeed(entropyToMnemonic(entropy))
      this._keyrings[name] = new Keyring(seed)
      this._subDIDs[name] = await this._init3ID(name)
      localstorage.set(STORAGE_KEY + this.managementAddress, this.serializeState())
      return true
    } else {
      return false
    }
  }

  async getPublicKeys (space, uncompressed) {
    let pubkeys
    if (this._has3idProv) {
      pubkeys = Object.assign({}, space ? this._pubkeys.spaces[space] : this._pubkeys.main)
      if (uncompressed) {
        pubkeys.signingKey = Keyring.uncompress(pubkeys.signingKey)
      }
    } else {
      pubkeys = this._keyringBySpace(space).getPublicKeys(uncompressed)
      pubkeys.managementKey = this.managementAddress
    }
    return pubkeys
  }

  async encrypt (message, space, to) {
    const keyring = this._keyringBySpace(space)
    let paddedMsg = typeof message === 'string' ? _pad(message) : message
    if (to) {
      return keyring.asymEncrypt(paddedMsg, to)
    } else {
      return keyring.symEncrypt(paddedMsg)
    }
  }

  async decrypt (encObj, space, toBuffer) {
    const keyring = this._keyringBySpace(space)
    let paddedMsg
    if (encObj.ephemeralFrom) {
      paddedMsg = keyring.asymDecrypt(encObj.ciphertext, encObj.ephemeralFrom, encObj.nonce, toBuffer)
    } else {
      paddedMsg = keyring.symDecrypt(encObj.ciphertext, encObj.nonce, toBuffer)
    }
    return toBuffer ? paddedMsg : _unpad(paddedMsg)
  }

  _pad (val, blockSize = ENC_BLOCK_SIZE) {
    const blockDiff = (blockSize - (val.length % blockSize)) % blockSize
    return `${val}${'\0'.repeat(blockDiff)}`
  }

  _unpad (padded) {
    return padded.replace(/\0+$/, '')
  }

  _keyringBySpace (space) {
    return space ? this._keyrings[space] : this._mainKeyring
  }

  logout () {
    localstorage.remove(STORAGE_KEY + this.managementAddress)
    this.stopUpdatePolling()
  }

  stopUpdatePolling () {
    if (this._pollInterval) {
      clearInterval(this._pollInterval)
    }
  }

  static isLoggedIn (address) {
    return Boolean(localstorage.get(STORAGE_KEY + address.toLowerCase()))
  }

  static async getIdFromEthAddress (address, provider, ipfs, wallet, opts = {}) {
    opts.has3idProv = Boolean(provider.is3idProvider)
    if (opts.has3idProv) {
      return new ThreeId(provider, ipfs, keystore, opts)
    } else {
      const normalizedAddress = address.toLowerCase()
      let serialized3id = localstorage.get(STORAGE_KEY + normalizedAddress)
      if (serialized3id) {
        if (opts.consentCallback) opts.consentCallback(false)
      } else {
        let sig
        if (opts.contentSignature) {
          sig = opts.contentSignature
        } else {
          const text = 'This app wants to view and update your 3Box profile.'
          var msg = '0x' + Buffer.from(text, 'utf8').toString('hex')
          sig = await wallet.signMessage(msg)
        }
        if (opts.consentCallback) opts.consentCallback(true)
        const entropy = '0x' + sha256(sig.slice(2))
        const mnemonic = entropyToMnemonic(entropy)
        const seed = mnemonicToSeed(mnemonic)
        serialized3id = JSON.stringify({
          managementAddress: normalizedAddress,
          seed,
          spaceSeeds: {}
        })
      }
      const threeId = new ThreeId(provider, ipfs)
      threeId._initKeys(serialized3id)
      await threeId._initDID()
      return threeId
    }
  }
}

const createMuportDocument = (signingKey, managementKey, asymEncryptionKey) => {
  return {
    version: 1,
    signingKey,
    managementKey,
    asymEncryptionKey
  }
}

module.exports = ThreeId
