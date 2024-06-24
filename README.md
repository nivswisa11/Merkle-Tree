# Merkle Tree with RSA Signature

This repository contains a Python implementation of a Merkle Tree with functionalities for generating RSA keys, signing the Merkle Tree root, and verifying the signatures. The Merkle Tree ensures data integrity, while RSA provides cryptographic signing and verification.
This project was developed as part of the course Communication Security.



## Prerequisites

To run the code, you need to have the following:

- Python 3.x
- `cryptography` library

You can install the required library using pip:

```sh
pip install cryptography
```

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/guyreuveni33/merkle-tree.git
   ```
2. Navigate to the project directory:

   ```sh
   cd merkle-tree
   ```

## Usage

The script reads commands from standard input. Below are the available commands:

1. **Add a Leaf**: 
    ```sh
    1 <data>
    ```
    Adds a new leaf to the Merkle Tree with the given data.

2. **Calculate Root**:
    ```sh
    2
    ```
    Calculates and prints the root of the Merkle Tree.

3. **Get Proof of Inclusion**:
    ```sh
    3 <index>
    ```
    Prints the root and proof of inclusion for the leaf at the given index.

4. **Verify Proof of Inclusion**:
    ```sh
    4 <data> <root> <proof>
    ```
    Verifies the proof of inclusion for the given data and prints the result (True/False).

5. **Generate RSA Keys**:
    ```sh
    5
    ```
    Generates and prints a new pair of RSA private and public keys.

6. **Sign Root**:
    ```sh
    6 <private_key>
    ```
    Signs the Merkle Tree root with the provided private key and prints the signature.

7. **Verify Signature**:
    ```sh
    7 <public_key> <signature> <data>
    ```
    Verifies the signature against the provided data using the public key and prints the result (True/False).

### Example

Here's an example of how you might use the script interactively:

```sh
python merkle_rsa.py

# Adding leaves
1 apple
1 orange
1 banana

# Calculating root
2
# Output: <root_hash>

# Getting proof of inclusion for the second leaf (index 1)
3 1
# Output: <root_hash> <proof>

# Verifying proof
4 orange <root_hash> <proof>
# Output: True

# Generating RSA keys
5
# Output: <private_key>
# Output: <public_key>

# Signing the root
6 <private_key>
# Output: <signature>

# Verifying the signature
7 <public_key> <signature> <root_hash>
# Output: True
```

## Explanation

The code consists of the following components:

- **MerkleTree Class**:
  - `add_leaf(data: str)`: Adds a new leaf to the tree by hashing the data and storing the hash.
  - `calculate_root()`: Calculates and returns the root of the tree.
  - `_calculate_root(nodes)`: Recursively calculates the root hash of the tree from the leaf nodes.
  - `_hash_pair(left, right)`: Hashes a pair of nodes together.
  - `get_proof_of_inclusion(index)`: Gets the proof of inclusion for a specific leaf node.
  - `verify_proof(data, root, proof)`: Verifies the proof of inclusion for a specific piece of data.
  - `generate_rsa_keys()`: Generates a new pair of RSA keys, both private and public.
  - `sign_root(private_key)`: Signs the root hash of the Merkle tree with a private RSA key.
  - `verify_signature(public_key, signature, data)`: Verifies a signature against some data using a public RSA key.

## License

This project is licensed under the MIT License.

Feel free to explore, modify, and use the code according to the terms of the license.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Contact

For questions or feedback, please contact us.
Made by Niv swisa and Guy Reuveni
