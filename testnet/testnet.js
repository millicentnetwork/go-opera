
const Web3 = require('web3');


const ftmNetwork = 'http://127.0.0.1:3000';
const web3 = new Web3(new Web3.providers.HttpProvider(ftmNetwork));

console.log(web3)
