import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption

class MerkleTree:
    def __init__(self):
        self.leaves = []  # Initialize an empty list to store the leaves of the Merkle tree

    def add_leaf(self, data: str):
        # Add a new leaf to the tree by hashing the data and storing the hash
        leaf_hash = hashlib.sha256(data.encode()).hexdigest()
        self.leaves.append(leaf_hash)

    def calculate_root(self):
        # Calculate the root of the tree
        if not self.leaves:
            return ''
        return self._calculate_root(self.leaves)

    def _calculate_root(self, nodes):
        # Recursively calculate the root hash of the tree from the leaf nodes
        while len(nodes) > 1:
            new_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    new_level.append(self._hash_pair(nodes[i], nodes[i + 1]))
                else:
                    new_level.append(nodes[i])  # If there's an odd number of nodes, keep the last one
            nodes = new_level
        return nodes[0]

    def _hash_pair(self, left, right):
        # Hash a pair of nodes together
        return hashlib.sha256((left + right).encode()).hexdigest()

    def get_proof_of_inclusion(self, index):
        # Get the proof of inclusion for a specific leaf node
        if index < 0 or index >= len(self.leaves):
            return ''
        proof = []
        nodes = self.leaves[:]
        current_index = index
        while len(nodes) > 1:
            new_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    pair_hash = self._hash_pair(nodes[i], nodes[i + 1])
                    if i == current_index or i + 1 == current_index:
                        if i != current_index:
                            proof.append('0' + nodes[i])
                        else:
                            proof.append('1' + nodes[i + 1])
                        current_index = len(new_level)
                else:
                    pair_hash = nodes[i]
                    if i == current_index:
                        current_index = len(new_level)
                new_level.append(pair_hash)
            nodes = new_level
        return ' '.join(proof)

    def verify_proof(self, data, root, proof):
        # Verify the proof of inclusion for a specific piece of data
        current_hash = hashlib.sha256(data.encode()).hexdigest()
        for p in proof.split():
            direction = p[0]
            hash_value = p[1:]
            if direction == '0':
                current_hash = self._hash_pair(hash_value, current_hash)
            else:
                current_hash = self._hash_pair(current_hash, hash_value)
        return current_hash == root

    def generate_rsa_keys(self):
        # Generate a new pair of RSA keys both private and public
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).decode()
        # Modify the private key headers to match RSA format
        private_key = private_key.replace("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----")
        private_key = private_key.replace("-----END PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")

        public_key = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return private_key, public_key

    def sign_root(self, private_key):
        # Sign the root hash of the Merkle tree with a private RSA key
        root = self.calculate_root()
        if not root:
            return ''
        private_key = load_pem_private_key(private_key.encode(), password=None)
        signature = private_key.sign(
            root.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, public_key, signature, data):
        # Verify a signature against some data using a public RSA key
        public_key = load_pem_public_key(public_key.encode())
        signature = base64.b64decode(signature)
        try:
            public_key.verify(
                signature,
                data.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Verification failed: {e}")
            return False

if __name__ == "__main__":
    import sys
    tree = MerkleTree()
    reading_private_key = False
    reading_public_key = False
    reading_signature = False
    private_key_lines = []
    public_key_lines = []
    signature = ''
    text = ''

    # Reading lines from standard input and processing commands
    for line in sys.stdin:
        line = line.strip()
        if reading_private_key:
            private_key_lines.append(line)
            if line == "-----END RSA PRIVATE KEY-----":
                private_key = "\n".join(private_key_lines)
                print(tree.sign_root(private_key))
                reading_private_key = False
                private_key_lines = []
        elif reading_public_key:
            public_key_lines.append(line)
            if line == "-----END PUBLIC KEY-----":
                public_key = "\n".join(public_key_lines)
                reading_public_key = False
                reading_signature = True
        elif reading_signature:
            signature += line
            if '==' in signature:
                signature, text = signature.split(' ', 1)
                print(tree.verify_signature(public_key, signature, text.strip()))
                reading_signature = False
                public_key_lines = []
                signature = ''
                text = ''
        else:
            if line.startswith('1 '):
                tree.add_leaf(line[2:].strip())
            elif line.startswith('2'):
                print(tree.calculate_root())
            elif line.startswith('3 '):
                index = int(line[2:].strip())
                root = tree.calculate_root()
                proof = tree.get_proof_of_inclusion(index)
                print(f"{root} {proof}")
            elif line.startswith('4 '):
                parts = line[2:].strip().split(' ', 1)
                data = parts[0]
                proof_info = parts[1].split(' ', 1)
                root = proof_info[0]
                proof = proof_info[1]
                print(tree.verify_proof(data, root, proof))
            elif line.startswith('5'):
                private_key, public_key = tree.generate_rsa_keys()
                print(private_key)
                print(public_key)
            elif line.startswith('6 '):
                reading_private_key = True
                private_key_lines.append(line[2:].strip())
            elif line.startswith('7 '):
                reading_public_key = True
                public_key_lines.append(line[2:].strip())
            else:
                print()
