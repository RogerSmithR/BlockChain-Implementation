# BlockChain-Implementation
The project is focused on implementing Bitcoin blockchain data structures in C#
## Key Tasks:
- User and Key Pair Generation: The project starts by defining six users and creating EC (Elliptic Curve) public key pairs for each user.
- Transaction Creation: Transactions are created between the six users. Initially, one user possesses all the coins (e.g., 100 coins), which are then transferred to other users and traded between them. This step involves understanding BTC transaction data structures, EC encryption/decryption, and EC signatures. Each transaction requires a new public/private key pair, and when a sender spends a portion of their coins, they create a new key pair to receive the change.
- Merkle Tree Creation: A Merkle tree is generated for the transactions. A Merkle tree involves hashing and DSA (Digital Signature Algorithm) signatures.
- Genesis Block: The project includes creating the Genesis block, the first block in the Bitcoin blockchain.
- Block Addition: Three additional blocks are added to the Genesis block, each containing four transactions. These transactions are assumed to be single-input-single-output transactions for simplicity.
- Cryptographic Primitives Verification: The program must verify that each cryptographic primitive is implemented correctly.
- The desired output of the project includes displaying all three blocks and the transactions contained within them as they occur. This involves showing all the required fields for each block and transaction. Additionally, the program should calculate and display the balance of each account after the 12 transactions. It's mentioned that you can hardcode the transaction information/data in your code.

## Run the code:
You can copy and paste the code on the folowing site:
https://dotnetfiddle.net/
[https://dotnetfiddle.net/]
