import asyncio
import websockets
import json
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

client_host = "localhost"
client_port = 54321 # Test purpose only

# Generate a new RSA-4096 key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)
public_key = private_key.public_key() # Private key object has a method to get the public key
# Serialise the public key to PEM format for sharing (as per SOCP)
pem = public_key.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo
)
# SOCP requires URL-safe base64 encoding without padding
pubkey_b64 = base64.urlsafe_b64encode(pem).rstrip(b'=').decode('ascii')

def load_config():
    try:
        with open('config.json', 'r') as f:
            config_data = json.load(f)
            return config_data['bootstrap_servers']
    
    except Exception as e:
        print(f"Error loading config: {e}")
        return []

async def join_network():
    bootstrap_servers = load_config()
    if not bootstrap_servers:
        return
    
    # Loop through the servers to find one that's online
    for server in bootstrap_servers:
        uri = f"ws://{server['host']}:{server['port']}"
        try:
            # Establish a WebSocket connection to the server
            async with websockets.connect(uri) as websocket:
                print(f"Connected to introducer server at {uri}")
                client_id = str(uuid.uuid4()) # Unique ID for this client
                
                request = {
                    "type": "SERVER_HELLO_JOIN",
                    "from": client_id,
                    "to": f"{server['host']}:{server['port']}",
                    "ts": int(time.time() * 1000),
                    "payload": {
                        "host": client_host,
                        "port": client_port,
                        "pubkey": pubkey_b64
                    }
                }
                print(f"Sending join request: {request}")
                await websocket.send(json.dumps(request)) # Send join request
                response_str = await websocket.recv() # Wait for and receive a response
                print(json.dumps(json.loads(response_str), indent=2)) # Pretty-print the JSON response

                return # Exit after successful connection

        except ConnectionRefusedError:
            print(f"Connection to {uri} failed. Trying next server...")
            continue # Try next server in list
    
    print("Could not connect to any introducer servers.")


if __name__ == "__main__":
    asyncio.run(join_network())