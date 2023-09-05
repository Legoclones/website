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