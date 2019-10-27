const { generateMnemonic, getSeedFromMnemonic } = require('./src/Mnemonic')
const { getMultiSignAddress, getAddress, getDid } = require('./src/Address')
const Transaction = require('./src/Transaction')
const {
    getMasterPrivateKey,
    getMasterPublicKey,
    getBip32ExtendedPrivateKey,
    getBip32ExtendedPublicKey,
    getAccountExtendedPrivateKey,
    getAccountExtendedPublicKey,
    getDerivedPrivateKey,
    getDerivedPublicKey,
    getRootPrivateKey,
    getSinglePrivateKey,
    getSinglePublicKey,
    getPublicKeyFromPrivateKey,
    generateSubPrivateKey,
    generateSubPublicKey,
    getIdChainMasterPublicKey,
    generateIdChainSubPrivateKey,
    generateIdChainSubPublicKey,
    sign,
    verify,
} = require('./src/Api')

module.exports = {
    generateMnemonic,
    getSeedFromMnemonic,
    getMultiSignAddress,
    getAddress,
    getDid,
    getMasterPrivateKey,
    getMasterPublicKey,
    getBip32ExtendedPrivateKey,
    getBip32ExtendedPublicKey,
    getAccountExtendedPrivateKey,
    getAccountExtendedPublicKey,
    getDerivedPrivateKey,
    getDerivedPublicKey,
    getRootPrivateKey,
    getSinglePrivateKey,
    getSinglePublicKey,
    getPublicKeyFromPrivateKey,
    generateSubPrivateKey,
    generateSubPublicKey,
    getIdChainMasterPublicKey,
    generateIdChainSubPrivateKey,
    generateIdChainSubPublicKey,
    sign,
    verify,
    Transaction,
}
