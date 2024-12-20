import requests
from mnemonic import Mnemonic
from bip32 import BIP32
import ecdsa
import hashlib
import base58

# Function to generate a 12-word seed phrase
def generate_seed_phrase():
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)  # 128 bits = 12 words

# Function to derive the Bitcoin address from the seed phrase
def derive_address(seed_phrase):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(seed_phrase)
    bip32 = BIP32.from_seed(seed)
    
    # Derive the first private key
    private_key = bip32.get_privkey_from_path("m/44'/0'/0'/0/0")
    
    # Generate the public key from the private key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()  # Uncompressed public key

    # Generate the Bitcoin address from the public key
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    public_key_hash = ripemd160.digest()

    # Add version byte (0x00 for mainnet)
    versioned_payload = b'\x00' + public_key_hash

    # Calculate checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]

    # Create the final address
    address = base58.b58encode(versioned_payload + checksum).decode('utf-8')
    return address

# Function to check balance using BlockCypher API
def check_balance(address):
    url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
    response = requests.get(url)
    if response.status_code == 200:
        balance_info = response.json()
        return balance_info['final_balance'] / 1e8  # Convert satoshis to BTC
    else:
        print("Error fetching balance:", response.json())
        return None

# Function to print wallets with balance greater than 0
def print_wallets_with_positive_balance(wallets):
    """
    This function prints wallet addresses with a balance greater than 0.
    
    Parameters:
    wallets (dict): A dictionary where keys are wallet addresses and values are balances.
    """
    print("Wallets with balance greater than 0:")
    for address, balance in wallets.items():
        if balance > 0:
            print(f"Address: {address}, Balance: {balance:.8f} BTC")

# Main function to generate the seed phrase, derive address, and check balance
def main():
    wallets = {}
    
    # Generate a seed phrase and derive an address
    seed_phrase = generate_seed_phrase()
    print("Your 12-word seed phrase is:", seed_phrase)
    
    address = derive_address(seed_phrase)
    print("Derived Address:", address)
    
    # Check balance and store in wallets dictionary
    balance = check_balance(address)
    if balance is not None:
        wallets[address] = balance
        print(f"Balance for address {address}: {balance:.8f} BTC")
    else:
        print("Failed to retrieve balance.")
    
    # Print wallets with positive balance
    print_wallets_with_positive_balance(wallets)

# Run the main function
if __name__ == "__main__":
    main()
