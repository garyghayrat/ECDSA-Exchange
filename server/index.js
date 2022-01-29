const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;

const SHA256 = require('crypto-js/sha256');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');

const key1 = ec.genKeyPair();
const key2 = ec.genKeyPair();
const key3 = ec.genKeyPair();

const publicKey1 = key1.getPublic().encode('hex');
const publicKey2 = key2.getPublic().encode('hex');
const publicKey3 = key3.getPublic().encode('hex');

const privateKey1 = key1.getPrivate().toString(16);
const privateKey2 = key2.getPrivate().toString(16);
const privateKey3 = key3.getPrivate().toString(16);

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

const balances = {
  [publicKey1]: 100,
  [publicKey2]: 50,
  [publicKey3]: 75,
}

console.log("Address 1 public key: " + publicKey1 + " with balance of " + balances[publicKey1] + " ETH");
console.log("Address 2 public key: " + publicKey2 + " with balance of " + balances[publicKey2] + " ETH");
console.log("Address 3 public key: " + publicKey3 + " with balance of " + balances[publicKey3] + " ETH");

console.log("");

console.log("Address 1 private key: " + privateKey1);
console.log("Address 2 private key: " + privateKey2);
console.log("Address 3 private key: " + privateKey3);

app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, recipient, amount, signature} = req.body;

  var checkHash = SHA256(sender).toString();
  console.log(signature);
  console.log(ec.keyFromPublic(sender, 'hex').verify(checkHash, signature));

  if(ec.keyFromPublic(sender, 'hex').verify(checkHash, signature)) {
    
  balances[sender] -= amount;
  balances[recipient] = (balances[recipient] || 0) + +amount;

  }

  res.send({ balance: balances[sender] });
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});
