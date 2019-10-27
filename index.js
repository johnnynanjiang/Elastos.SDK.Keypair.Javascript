//const { generateMnemonic, getSeedFromMnemonic } = require('./src/Mnemonic')
const { getMultiSignAddress, getAddress, getDid } = require('./src/Address')
//const Transaction = require('./src/Transaction')
const {
    getMasterPrivateKey,
    getMasterPublicKey,
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
    //generateMnemonic,
    //getSeedFromMnemonic,
    getMultiSignAddress,
    getAddress,
    getDid,
    getMasterPrivateKey,
    getMasterPublicKey,
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
    //Transaction,
}
