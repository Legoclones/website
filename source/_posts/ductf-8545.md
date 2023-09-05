---
title: Writeup - EightFiveFourFive (DUCTF 2023)
date: 2023-09-04 00:00:00
tags: 
- writeup
- blockchain
- ductf2023
---

# DUCTF 2023 - EightFiveFourFive
## Description
```markdown
Warming up, let's get you setup and make sure you can connect to the blockchain 
infra ok :). Your challenge is to ensure the `isSolved()` function returns true!

Author: Blue Alder

[EightFiveFourFive.sol]
```

## Writeup
Alright this is the first blockchain challenge I've ever completed, and it was pretty much just a test to make sure you know how to connect to their infra. I'm not a blockchain guy nor do I ever really intend to get super deep into blockchain, but even just trying to figure out how to connect to the infra took me a while and online resources weren't very helpful, so I felt it was important to document this for absolute blockchain beginners like me. 

First, [here is the `.sol` file](/static/ductf-8545/EightFiveFourFive.sol):

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract EightFiveFourFive {
    string private use_this;
    bool public you_solved_it = false;

    constructor(string memory some_string) {
        use_this = some_string;
    }

    function readTheStringHere() external view returns (string memory) {
        return use_this;
    }

    function solve_the_challenge(string memory answer) external {
        you_solved_it = keccak256(bytes(answer)) == keccak256(bytes(use_this));
    }

    function isSolved() external view returns (bool) {
        return you_solved_it;
    }
}
```

This file defines a smart contract called `EightFiveFourFive` that we just need to interact with. The syntax looks pretty similar to many programming languages, so it's not too hard to understand. The description states you need to call `isSolved()` and have it return true, meaning that the `you_solved_it` variable needs to be set to true. In the top of the contract, it's defined to false, so we need to change that using the `solve_the_challenge()` function. This function takes the Keccak-256 hash of two variables and compares them, if the hashes are the same then `you_solved_it` will be true!

The two variables are `answer` and `use_this`. `answer` is passed as an argument to the function, meaning WE pass that variable when we call the function. The `use_this` variable is set when the contract is created, and since it's not hard-coded we have to call the `readTheStringHere()` function to get it. 

So solve chain is:

1. Call `readTheStringHere()` and save the output.
2. Pass that output as the sole parameter of `solve_the_challenge()` and call it.
3. Call `isSolved()`

### Infrastructure
Just before we get into the Python code for interacting with the contract, I just want to show what the per-team instances looked like and what information is provided.

<img src="/static/ductf-8545/infra.png" width="860px">

This beautiful UI contains the smart contract again, restates the goal, and displays the following information:

* Player Balance - `1.0 ETH`
    * Every transaction requires ETH to make, so your wallet is pre-initialized with more than enough
* Player Wallet Address - `0x81ECd1984be45000Af31A83D09e78aCa762900A0`
    * This identifies YOU publicly
* Private Key - `0xd87d832e7214bef73f205f2c10f7e73ab3a223f6473fc8480c01e91d75d38ed2`
    * This authenticates you as the owner of the wallet
* Contract Address - `0xf22cB0Ca047e88AC996c17683Cee290518093574`
    * This is where the smart contract resides and is the addresses to interact with it
* RPC URL - `https://blockchain-eightfivefourfive-d9ce32dd4aeaea69-eth.2023.ductf.dev:8545`
    * This is your entrypoint into the blockchain infrastructure
* Chain ID and Block Time (<i>tbh no idea what they are but I didn't need them</i>)

### Creating Solve Script
I used the `web3` Python library to solve this challenge. Even though this is a simple blockchain challenge, there are still quite a few lines to fill out. First, we're going to start by making constants with the above info, create a `Web3` Python object to interact with, and use our private key to authenticate to our account. 

```python
from web3 import Web3


### CONSTANTS ###
RPC_URL = "https://blockchain-eightfivefourfive-d9ce32dd4aeaea69-eth.2023.ductf.dev:8545"
PRIVATE_KEY = "0xd87d832e7214bef73f205f2c10f7e73ab3a223f6473fc8480c01e91d75d38ed2"
PLAYER_ADDRESS = "0x81ECd1984be45000Af31A83D09e78aCa762900A0"
CONTRACT_ADDRESS = "0xf22cB0Ca047e88AC996c17683Cee290518093574"


### INITIALIZATIONS ###
w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIVATE_KEY)
```

Now we need to create a contract object, linked to the `CONTRACT_ADDRESS` and initializing using the contract's ABI. The ABI is standardized JSON that defines data and functions contained within the contract, and is parsed from the actual `.sol` file. To obtain the ABI for `EightFiveFourFive.sol`, I went to https://remix.ethereum.org/ and had it do it online. You right-click in File Explorer and upload the `.sol` file.

<img src="/static/ductf-8545/upload.png" width="350px">

After doing this, I noticed a red line under the solidity version. In order to get the ABI, you need to compile the `.sol` file, and make sure that the compiler version matches the `pragma` line in the contract. I swtiched it to `0.8.19+commit.7dd6d404` (removing the underline), and pressed the Compile button. 

<img src="/static/ductf-8545/compile.png" width="800px">

After doing that, a few more buttons will appear in that same tab, one of which says ABI. You just click that to copy the ABI JSON to your clipboard.

<img src="/static/ductf-8545/abi.png" width="400px">

Okay, now that we have the ABI, we can now initialize our contract object in our Python script. 

```python
### CONTRACT SETUP ###
CONTRACT_ABI = [
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "some_string",
				"type": "string"
			}
		],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [],
		"name": "isSolved",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "readTheStringHere",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "answer",
				"type": "string"
			}
		],
		"name": "solve_the_challenge",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "you_solved_it",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
```

### Interacting with the Smart Contract
Now that the solve script is set up and initialized, we can now follow our solve chain to get the flag. As a reminder, this is it:

1. Call `readTheStringHere()` and save the output.
2. Pass that output as the sole parameter of `solve_the_challenge()` and call it.
3. Call `isSolved()`

To get the `use_this` variable from the `readTheStringHere()` function, you do the following:

```python
# Step 1 - call readTheStringHere() and save the output
use_this = contract.functions.readTheStringHere().call()
print("use_this: ", use_this)
```

This output the string `"I can connect to the blockchain!"`, which is our magic phrase! Now to call the next function, a little more setup is needed and a transaction will go through. 

```python
# Step 2 - call solve_the_challenge() with the output from step 1
transaction = contract.functions.solve_the_challenge(use_this).build_transaction({
    'from': PLAYER_ADDRESS,
    'nonce': w3.eth.get_transaction_count(PLAYER_ADDRESS),
    'gas': 210000,
    'gasPrice': w3.to_wei('50', 'gwei')
})
signed_transaction = w3.eth.account.sign_transaction(transaction, PRIVATE_KEY)
transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)

print(f"Transaction hash: {transaction_hash.hex()}")
print(f"Transaction status: {transaction_receipt.status}")
print(dict(transaction_receipt))
```

Now if you're wondering how the nonce is created, where the gas amount comes from, or even what `Wei` is, I have no idea. I just know it works and this is how you interact with it. Just like how wallets and contracts have hash addresses, so do transactions. After making a call to `solve_the_challenge()` with the `use_this` variable, you wait for a transaction receipt to ensure everything worked out right. 

The last step is to call `isSolved()`, and then you can get the flag from the infrastructure!

```python
# Step 3 - called isSolved() to check if the challenge is solved
solved = contract.functions.isSolved().call()
print(solved)
```

### Solve
This is our whole [solve script](/static/ductf-8545/solve.py):

```python
from web3 import Web3


### CONSTANTS ###
RPC_URL = "https://blockchain-eightfivefourfive-d9ce32dd4aeaea69-eth.2023.ductf.dev:8545"
PRIVATE_KEY = "0xd87d832e7214bef73f205f2c10f7e73ab3a223f6473fc8480c01e91d75d38ed2"
PLAYER_ADDRESS = "0x81ECd1984be45000Af31A83D09e78aCa762900A0"
CONTRACT_ADDRESS = "0xf22cB0Ca047e88AC996c17683Cee290518093574"


### INITIALIZATIONS ###
w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIVATE_KEY)


### CONTRACT SETUP ###
CONTRACT_ABI = [
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "some_string",
				"type": "string"
			}
		],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [],
		"name": "isSolved",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "readTheStringHere",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "answer",
				"type": "string"
			}
		],
		"name": "solve_the_challenge",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "you_solved_it",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)


# Step 1 - call readTheStringHere() and save the output
use_this = contract.functions.readTheStringHere().call()
print("use_this: ", use_this)


# Step 2 - call solve_the_challenge() with the output from step 1
transaction = contract.functions.solve_the_challenge(use_this).build_transaction({
    'from': PLAYER_ADDRESS,
    'nonce': w3.eth.get_transaction_count(PLAYER_ADDRESS),
    'gas': 210000,
    'gasPrice': w3.to_wei('50', 'gwei')
})
signed_transaction = w3.eth.account.sign_transaction(transaction, PRIVATE_KEY)
transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)

print(f"Transaction hash: {transaction_hash.hex()}")
print(f"Transaction status: {transaction_receipt.status}")
print(dict(transaction_receipt))


# Step 3 - called isSolved() to check if the challenge is solved
solved = contract.functions.isSolved().call()
print(solved)
```

This is the output when we run it:
```
use_this:  I can connect to the blockchain!
Transaction hash: 0x94b7bc0138200129956f27d3af07874248363a28ef26d324ed426dc47019f0e4
Transaction status: 1
{'blockHash': HexBytes('0x84e3898c84f6461b643b6969a03589e70e6fc7ef198c1c9159a17b8438ab5c83'), 'blockNumber': 5, 'contractAddress': None, 'cumulativeGasUsed': 26149, 'effectiveGasPrice': 50000000000, 'from': '0x81ECd1984be45000Af31A83D09e78aCa762900A0', 'gasUsed': 26149, 'logs': [], 'logsBloom': HexBytes('0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'), 'status': 1, 'to': '0xf22cB0Ca047e88AC996c17683Cee290518093574', 'transactionHash': HexBytes('0x94b7bc0138200129956f27d3af07874248363a28ef26d324ed426dc47019f0e4'), 'transactionIndex': 0, 'type': 0}
True
```

Then you back to the webpage and press "Get Flag"!

<img src="/static/ductf-8545/solve.png" width="800px">

**Flag:** `DUCTF{I_can_connect_to_8545_pretty_epic:)}`