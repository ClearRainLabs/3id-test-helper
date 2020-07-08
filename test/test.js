/* global describe, before, it, after */

import DidTestHelpers from '../src/index'
import didJWT from 'did-jwt'
import { Resolver } from 'did-resolver'
import { getResolver } from '3id-resolver'
import IPFS from 'ipfs'
import { assert } from 'chai'

const testKeys = ['0x2f03bbd84a197aac98e0e15c6b41ce0135725a02a30e07e2355e27ecf95bf91d',
  '0x900c8bf6d4848f99dc8fb2c65954c786478fbbe9a3a0ab0e4d3843e787761463',
  '0x945acd117f27c8c75184ba74a49186c39c44b4cf296c969ff8384ce32967c00b',
  '0xb4dc42f2b339a688ab2a335ef6d4d7c67de019a4023a87295f7baff7e329c060',
  '0x53e45087bb8ba4a52aea2df4be0986e0065f70bdb99fc138e086de4a66a144ff',
  '0x6e88827f409751df108d2047076a41c99654f682c5dc75ceacbed157d0ca83e8',
  '0xec6caf23a637fe5db8addb2cb10573fc883e91e8fdf334bb7d5f8cfb415a0ef3',
  '0xbb878e72f775890580dd02a8f3fe81d2908152acf4f8f57996708d57059ce089',
  '0x5cf6d7f3910f18d720c1d900c7913b9e7d6676299ee1379feb0451b55d65e43b',
  '0xad60a821491cff10c77cc096c5bc3874d24944b7880a7b8e10fca1f9f4180ecd']

describe('DID gen tests', function () {
  let ipfs
  let testHelper
  let accounts
  let owner

  before(async function () {
    ipfs = await IPFS.create()
    testHelper = new DidTestHelpers(ipfs)
  })

  after(function () {
    ipfs.stop()
  })

  describe('test helper class', function () {
    it('creates helper class', async function () {
      assert.typeOf(testHelper.signers, 'object')
    })

    it('generates accounts with test keys', async function () {
      accounts = await testHelper.generateAccounts(testKeys)
      assert.equal(accounts[0], 'did:3:bafyreiemia3l2kswmdntoq6uk47nckhsb6fgttz5jjbzjcbvmcp3hwdmre')
    })

    it('generates random accounts', async function () {
      const randAccounts = await testHelper.generateAccounts()
      assert.typeOf(randAccounts, 'array')
      assert.equal(randAccounts[0].substring(0, 6), 'did:3:')
    })

    it('gets the owner account', async function () {
      owner = await testHelper.getOwner()
      assert.equal(owner, 'did:3:bafyreiewjn5bc7ntxy4ug4a6fhwynjir4vqhb4fdoqfztfbvju5ooguofu')
    })

    it('creates a JWT', async function () {
      const payload = {
        msg: 'OUR JWT',
        other: 'smthing smthing smthing'
      }

      const jwt = await testHelper.createJWTFromDID(accounts[0], payload)

      const threeIdResolver = getResolver(testHelper.getIPFS())

      const resolver = new Resolver(threeIdResolver)

      const verified = await didJWT.verifyJWT(jwt, { resolver })
      assert.equal(payload.msg, verified.payload.msg)
      assert.equal(payload.other, verified.payload.other)
    })

    it('exports private keys', function () {
      const privKeys = testHelper.getPrivateKeys()
      assert.equal(privKeys, testKeys)
    })
  })
})
