const { encoding } = require('bitcore-lib-p256')
const { Base58 } = encoding
const { getSeedFromMnemonic } = require('../src/Mnemonic')
const { getMultiSignAddress, getAddressFromPrivateKey, getAddress, getDid, getMultiSign } = require('../src/Address')
const Transaction = require('../src/Transaction')
const {
    getMasterPrivateKey,
    getMasterPublicKey,
    getBip32ExtendedPrivateKey,
    getBip32ExtendedPublicKey,
    getRootPrivateKey,
    getSinglePrivateKey,
    getSinglePublicKey,
    generateSubPrivateKey,
    generateSubPublicKey,
    getIdChainMasterPublicKey,
    generateIdChainSubPrivateKey,
    generateIdChainSubPublicKey,
    getPublicKeyFromPrivateKey,
    sign,
    verify,
} = require('../src/Api')

describe('Trust Wallet Core tests', function() {
    it('should derive from mnemonic', function() {
        const wordlist = 'shoot island position soft burden budget tooth cruel issue economy destroy above'
        const seed = '577cd910aede2582668a741d476b45e7998e905a4286f701b87b25923501f9d4ea19513b460bcccbc069ebbe4327a59af3d6463045c4b6fa21a5e7004ccfcc3e'

        expect(getSeedFromMnemonic(wordlist).toString('hex')).toBe(seed)

        // BIP32 Root Key in iancoleman.io/bip39/
        expect(getRootPrivateKey(seed)).toBe("xprv9s21ZrQH143K4bnrDwqpp9EwmpZPbQBLJefqcUkHG1Eb6gRzsrtuytGvNpzpuT8Prs3ubDPpp3EodHtdHvZCHuQCYPwDGvuHntB8qXPhiT1")

        // Account Extended Public Key in iancoleman.io/bip39/
        // m/44'/2305'/0'
        expect(getMasterPrivateKey(seed)).toBe("xprv9xz3iq3SDdk95hArvZuN89Qct6u5UNLGB3brATjPjPPhAcbDxf6vZuwASfZmyiUuBj8ZNxagaR6tUFauAoNusLQ6xkrfbeUxXbJdnmCNsMg")
        expect(getMasterPublicKey(seed)).toBe("xpub6ByQ8LaL41JSJBFL2bSNVHMMS8jZsq47YGXSxr91Hivg3QvNWCRB7iFeHy3na3y74dWPb7LhBCstHMMffqB3yxVQmxCsfFP24wc9fyAhfsy")

        // BIP32 Extended Private Key in iancoleman.io/bip39/
        // m/44'/2305'/0'/0
        expect(getBip32ExtendedPrivateKey(seed)).toBe("xprvA1sQLKGMBuxSGs4NjFqZZ53fVKUV7DPpWKnV7ZR8j1QzxZxq2rmwyfFyGUx5f3r4vh2EhTy6wxUcuxf5GV1otpaLsXkhJttFi6PrTan5WJX")
        expect(getBip32ExtendedPublicKey(seed)).toBe("xpub6ErkjpoF2HWjVM8qqHNZvCzQ3MJyWg7fsYi5uwpkHLwyqNHyaQ6CXTaT7kh4zkFP4u2o47K7G84uYYrDoxctMfPiAUo9nwjkeKMmM2YYnje")

        // m/44'/2305'/0'/0/0
        const prvKey0InBinary = generateSubPrivateKey(seed, coinType = 2305, changeChain = 0, index = 0)
        //const prvKey0InBase58 = Base58.encode(prvKey0InBinary)
        const pubKey0 = generateSubPublicKey(getMasterPublicKey(seed), changeChain = 0, index = 0).toString('hex')

        //expect(prvKey0InBase58).toBe("cQMwPtHBo1TqGX5hZDmKitbuKoA1R87WA97jy4TnEU8xh1hmwpLn")
        expect(pubKey0).toBe("0264ef40c21f18f7539f1d0926663392f9e18dee56046244c24d3b4ea6780a86e8")
        expect(getAddress(pubKey0)).toBe("EUHxgBacbyGNneLyZQPwp7hoHxWvCJYQqy")
    })
})