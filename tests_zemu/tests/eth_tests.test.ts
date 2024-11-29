/** ******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu, { ButtonKind, isTouchDevice } from '@zondax/zemu'
import { SeiApp } from '@zondax/ledger-sei'
import { ETH_PATH, EXPECTED_ETH_ADDRESS, EXPECTED_ETH_PK, EXPECTED_PK, defaultOptions, models } from './common'
import { ec } from 'elliptic'

jest.setTimeout(90000)

const sha3 = require('js-sha3')

const SIGN_TEST_DATA = [
  {
    name: 'transfer',
    op: '02f78205318402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c0',
    blindsign_required: false,
  },
  {
    name: 'asset_transfer',
    op: 'f87c01856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef8205318080',
    blindsign_required: true,
  },
  {
    name: 'asset_deposit',
    op: 'f87c01856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef8205318080',
    blindsign_required: true,
  },
  {
    name: 'legacy_transfer',
    op: 'ed01856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a24874000808205318080',
    blindsign_required: false,
  },
  {
    name: 'erc721_safe_transfer_from',
    op: '02f88f820531198459682f00850b68b3c16882caf09434bc797f40df0445c8429d485232874b1556172880b86442842e0e00000000000000000000000077944eed8d4a00c8bd413f77744751a4d04ea34a0000000000000000000000005d4994bccdd28afbbc6388fbcaaec69dd44c04560000000000000000000000000000000000000000000000000000000000000201c0',
    blindsign_required: true,
  },
  {
    name: 'erc721_safe_transfer_from_data',
    op: '02f90a758205318001018402625a009457f1887a8bf19b14fc0df6fd9b2acc9af147ea8580b90a50b88d4fde0000000000000000000000000565df3f5aad5a45d340b98d1e95f255e238cdc30000000000000000000000009ebfb53fa8526906738856848a27cb11b0285c3f307fa76847d6ec39c1c90ef3b279e83cbf6e0028a6b83e4187615fd74610a22b00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000984cd1d89fb00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000500000000000000000000000057f1887a8bf19b14fc0df6fd9b2acc9af147ea850000000000000000000000000565df3f5aad5a45d340b98d1e95f255e238cdc3000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000008a4e7acab240000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000058000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009ebfb53fa8526906738856848a27cb11b0285c3f00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000046000000000000000000000000000000000000000000000000000000000000004e0000000000000000000000000120f5e9ef7883b4b3fb8cf59abccd6cbb3221e32000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000632db0b000000000000000000000000000000000000000000000000000000000632f026700000000000000000000000000000000000000000000000000000000000000003d6ddb428fb83199f55e5d9db388798de7982e540559fdc8973690a3b311accd0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fd2439da2e500000000000000000000000000000000000000000000000000000fd2439da2e50000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000057f1887a8bf19b14fc0df6fd9b2acc9af147ea85b8e627e97e5a9c349ce0e7d8ca289210292aaa23c77320258af4030ac9b35adc00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000120f5e9ef7883b4b3fb8cf59abccd6cbb3221e320000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003cc103a500e000000000000000000000000000000000000000000000000000003cc103a500e00000000000000000000000000a7673ab3b0949a0efcd818c86c71fff7cd645ac70000000000000000000000000000000000000000000000000000000000000041a32300e377fe8acd87ecc64a6d759cbe16e561ee012bba31c0a1c673fc2e80f642b096e4cf17fc31a71af417fe090181f4857177fedd83a8e428603bfb88a8c01b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000307fa76847d6ec39c1c90ef3b279e83cbf6e0028a6b83e4187615fd74610a22b00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000117ea1dd9ecc2fc4f863e0f383029c6787ba379f80958abb3fc8bc079f21b514a1cdff5f9224fd75fe6e01e4e0edf41998ccec816bb377663d05fd874c7681e7f3f4217fa579ba41e2f7ac70b632bafd704573470ae765bdd96f5673cc4475ab8fac02a3f70665924a8bde9ad181df13581e883212c1cfa6bf4a425b1760375c121bbd09628c48138b7ddcfad9520da9ad39d97f9a17d48a8239fd52c38108507146e91239dcbdeec3e09e7eb4c8ea3ce3026575cd900cce8a208605810732619241d1b1703af8e17d3fbd76a4c074e7a8518c8ef63539d723a67a20a73abd5b393a595f5aa992d118b650564b2ac4d7e5c01753b7f4a79dd8d67ac158eadae3ea335dfed47134d7a0e65d4911c5d7eb0f99a2b5d8161479922a5150238ea7473b73beb96f9da02359c26071bf9bd1524780ccac98a6e2535330e7b1be7a3d21b29ceb65854902f22ad2eb9099724e8cfe03078f5db93b617c2050249203495594295765be35854719956ab6e36fed9dd9ab629c010525c9d20e9502727a7093f24717dc2d5d9f04333171bb1779f26370aae4912970f5e1b6c4778c0f3c7c672e5dd704d1fdcc69232ba5b996f1fed800b03e24acb02fef4214e0b46d01a515b600a6f5dcc80ac7a3753bff70bf1fb7557ce8dad801fec25bc7667244cc2e08f22981446ab788f9c223957f54016f4bb8870d9919b8316361f7332f5c2f01fad1ec9ac757a737872c4beb7cf800b714b2a0613be1fa3569f1531c23ef423fd29600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f656e732e766973696f6e1fc0',
    blindsign_required: true,
  },
  {
    name: 'erc721_approve_for_all',
    op: '02f87182053182034a8459682f00850322d538d182b67094bd3f82a81c3f74542736765ce4fd579d177b6bc580b844a22cb4650000000000000000000000001e0049783f008a0085193e00003d00cd54003c710000000000000000000000000000000000000000000000000000000000000001c0',
    blindsign_required: true,
  },
  {
    name: 'basic_transfer',
    op: 'eb80856d6e2edc00832dc6c094df073477da421520cf03af261b782282c304ad6684abcdef00808205318080',
    blindsign_required: false,
  },
  {
    name: 'legacy_contract_deploy',
    op: 'f85c80856d6e2edc00832dc6c08084abcdef00b8441a8451e6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008205318080',
    blindsign_required: true,
  },
  {
    name: 'legacy_contract_call',
    op: 'f84f80856d6e2edc00832dc6c09462650ae5c5777d1660cc17fcd4f48f6a66b9a4c284abcdef01a4ee919d5000000000000000000000000000000000000000000000000000000000000000018205318080',
    blindsign_required: true,
  },
  {
    name: 'basic_transfer_no_eip155',
    op: 'eb80856d6e2edc00832dc6c094df073477da421520cf03af261b782282c304ad6684a1bcd400808205318080',
    blindsign_required: false,
  },
  {
    name: 'contract_deploy_no_eip155',
    op: 'f85880856d6e2edc00832dc6c08001b8441a8451e6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008205318080',
    blindsign_required: true,
  },
  {
    name: 'erc20_transfer',
    op: 'f86e80856d6e2edc00832dc6c0941d80c49bbbcd1c0911346656b529df9e5c2f783d8203e8b844a9059cbb000000000000000000000000b7784e5ad303d44067d2a6353441b784c226ccaf00000000000000000000000000000000000000000000000000000000075bca008205318080',
    blindsign_required: false,
  },
  {
    name: 'undelegate_contract',
    op: 'ef80856d6e2edc00832dc6c094c67dce33d7a8efa5ffeb961899c73fe01bce92738203e886b302f39300018205318080',
    blindsign_required: true,
  },
  {
    name: 'deposit_dummy_contract',
    op: 'ed80856d6e2edc00832dc6c094c67dce33d7a8efa5ffeb961899c73fe01bce92738203e884b302f3938205318080',
    blindsign_required: true,
  },
]

describe.each(models)('ETHT', function (m) {
  test.concurrent('get address', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new SeiApp(sim.getTransport())

      const resp = await app.getEVMAddress(ETH_PATH, false, true)

      console.log(resp)

      console.log(resp.publicKey.toString())
      console.log(resp.address)

      expect(resp.publicKey.toString()).toEqual(EXPECTED_ETH_PK)
      expect(resp.address.toString()).toEqual(EXPECTED_ETH_ADDRESS)
    } finally {
      await sim.close()
    }
  })

  test.concurrent('show address', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new SeiApp(sim.getTransport())

      const resp = app.getEVMAddress(ETH_PATH, true, true)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_eth_address`)

      console.log(resp)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(SIGN_TEST_DATA)('sign transaction:  $name', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new SeiApp(sim.getTransport())
      const msg = data.op

      // Put the app in blind signing mode
      await sim.toggleBlindSigning()

      // do not wait here..
      const signatureRequest = app.signEVM(ETH_PATH, msg, null)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-eth-${data.name}`, true, 0, 15000, data.blindsign_required)

      let resp = await signatureRequest
      console.log(resp)

      const EC = new ec('secp256k1')
      const msgHash = sha3.keccak256(Buffer.from(msg, 'hex'))

      const pubKey = Buffer.from(EXPECTED_PK, 'hex')
      const signature_obj = {
        r: Buffer.from(resp.r, 'hex'),
        s: Buffer.from(resp.s, 'hex'),
      }

      // Verify signature
      const signatureOK = EC.verify(msgHash, signature_obj, pubKey, 'hex')
      expect(signatureOK).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
