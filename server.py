import asyncio
import websockets
import json
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import base64
import sqlite3

server_id = str(uuid.uuid4()) # Our server's unique ID
print(f"Server starting with ID: {server_id}")
server_db_file = "server_list.db"


# Generate server's RSA-4096 key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)
public_key = private_key.public_key()

servers = {} # Stores live connection object for each connected server
server_addrs = {} # Stores public address for each known server on the network
local_users = {} # Stores live connection object for each end-user connected directly to this server
user_locations = {} # Maps every known user to their location in the network
user_meta = {} # Maps user_ids to their metadata
user_pubkey = {}   # Store pubkeys of all users

server_pubkeys = {} # Maps server IDs to their public keys for signature verification

# A lot of help from "external sources" here, I was very stuck...
def sign_message(message):
    payload = message.get('payload', {})
    # Canonicalise the payload with sorted keys and no whitespace (as per SOCP)
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

    # Sign the canonicalised payload with our private key using PSS padding and SHA-256 hashing
    signature = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Encode the signature into base64url format without padding
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')
    # Add the signature to the message
    message['sig'] = signature_b64

    return message

async def verify_signature(message):
    # Verify the signature of a received message using the sender's public key ... True if valid, else False
    try:
        sender_id = message.get('from')
        signature_b64 = message.get('sig')
        payload = message.get('payload', {})
        # Get sender's pub key
        pubkey = server_pubkeys.get(sender_id)
        if not pubkey:
            print(f"Verification failed: Unknown sender {sender_id}")
            return False
        
        # Recreating the canonicalised payload
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = base64.urlsafe_b64decode(signature_b64 + '==') # Add padding back for decoding

        # Verify the signature, returns InvalidSignature exception if not valid
        pubkey.verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True

    except (InvalidSignature, TypeError, ValueError) as e:
        print(f"Verification failed for {sender_id}: {e}")
        return False
    
def init_db():
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()
    
    #incase of locking database from multiple accesses, adding busy timeout
    #also using WAL mode for better concurrency
    #by cary
    curr.execute("PRAGMA journal_mode=WAL;")
    curr.execute("PRAGMA synchronous=NORMAL;")
    curr.execute("PRAGMA busy_timeout=5000;")
    
    #create table inside .db file if it doesnt exist (capitalised text are keywords/constraints)
    curr.execute("""CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY, 
                pubkey TEXT NOT NULL, 
                privkey_store TEXT NOT NULL,
                username TEXT UNIQUE, 
                pake_password TEXT NOT NULL, 
                meta TEXT,
                version INTEGER NOT NULL
                )""")
    
    #servers table
    curr.execute("""CREATE TABLE IF NOT EXISTS servers (
                server_id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                pubkey TEXT NOT NULL,
                last_seen INTEGER,
                version INTEGER NOT NULL
                )""")
    
    #groups table, possible extension if we want to include group chats other than the public channel
    curr.execute("""CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                creator_id TEXT NOT NULL,
                created_at INTEGER,
                meta TEXT,
                version INTEGER NOT NULL
                )""")

    #group members table, same as groups table, this is just optional if we want groups
    curr.execute("""CREATE TABLE IF NOT EXISTS group_members(
                group_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                role TEXT,
                wrapped_key TEXT NOT NULL,
                added_at INT,
                PRIMARY KEY (group_id, member_id)
                )""")

    conn.commit()
    conn.close()

#adds or updates user, default of no metadata, and version 1
def update_user(user_id, pubkey, privkey_store, username, pake_password, meta=None, version=1):
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()

    #store json data as string if it is not empty.
    meta_json = json.dumps(meta) if meta else None
#so how it reads is, add or replace into this defined datatype called users, look for this tuple structure, and replace with provided values
    curr.execute("INSERT OR REPLACE INTO users (user_id, pubkey, privkey_store, username, pake_password, meta, version)" "VALUES (?, ?, ?, ?, ?, ?, ?)", (user_id, pubkey, privkey_store, username, pake_password, meta_json, version))
    conn.commit()
    conn.close()

def update_user_bulk(users):
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()

    #just a glorified for loop as a function
    values = [(u[0], u[1], u[2], u[3], u[4], json.dumps(u[5]) if u[5] else None, u[6]) for u in users]
    #method to bulk execute a tuple array? that uses the existing format
    curr.executemany("INSERT OR REPLACE INTO users (user_id, pubkey, privkey_store, username, pake_password, meta, version) VALUES (?, ?, ?, ?, ?, ?, ?)", values)
    conn.commit()
    conn.close()

#adds new user (not replace, throw exception if it isnt unique)
def add_new_user(user_id, pubkey, privkey_store, username, pake_password, meta=None, version=1):
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()

    #store json data as string if it is not empty.
    meta_json = json.dumps(meta) if meta else None
    #so how it reads is, add or replace into this defined datatype called users, look for this tuple structure, and replace with provided values
    curr.execute("INSERT INTO users (user_id, pubkey, privkey_store, username, pake_password, meta, version)" "VALUES (?, ?, ?, ?, ?, ?, ?)", (user_id, pubkey, privkey_store, username, pake_password, meta_json, version))
    conn.commit()
    conn.close()

def update_server(server_id, host, port, pubkey, last_seen=None, version=1):
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()
    if last_seen is None:
        #if not provided, set it to current time
        last_seen = int(time.time())

    curr.execute("INSERT OR REPLACE INTO servers (server_id, host, port, pubkey, last_seen, version) " "VALUES (?, ?, ?, ?, ?, ?)", (server_id, host, port, pubkey, last_seen, version))
    conn.commit()
    conn.close()

def get_user(user_id):
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()
    curr.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))

    row = curr.fetchone()
    conn.close()
    #if there is something, compile together data and return userdata, else nothing
    if row:
        user_data ={
            "user_id": row[0],
            "pubkey": row[1],
            "privkey_store": row[2],
            "username": row[3],
            "pake_password": row[4],
            #needs to specify json to load properly, since it is meta, it can be set to none if empty
            "meta": json.loads(row[5]) if row[5] else None,
            "version": row[6]
        }
        #returns as something usable, rather than just printing it
        return user_data
    return None

def get_pubkey_from_id(userid):
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()
    curr.execute("SELECT pubkey FROM users WHERE user_id = ?", (userid,))
    row = curr.fetchone()

    conn.close()
    if row:
        return row[0]
    return None

def get_server(server_id):
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()
    curr.execute("SELECT * FROM servers WHERE server_id = ?", (server_id,))
    row = curr.fetchone()
    conn.close()

    if row:
        server_data ={
            "server_id": row[0],
            "host": row[1],
            "port": row[2],
            "pubkey": row[3],
            "last_seen": row[4],
            "version": row[5]
        }
        return server_data
    return None

#additional method to list all known servers
def list_servers():
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()
    curr.execute("SELECT * FROM servers")
    rows = curr.fetchall()
    conn.close()

    servers = []
    for row in rows:
        servers.append({
            "server_id": row[0],
            "host": row[1],
            "port": row[2],
            "pubkey": row[3],
            "last_seen": row[4],
            "version": row[5]
        })
    return servers

def list_users():
    conn = sqlite3.connect(server_db_file)
    curr = conn.cursor()
    curr.execute("SELECT * FROM users")
    rows = curr.fetchall()
    conn.close()

    users = []
    for row in rows:
        users.append({
            "user_id": row[0],
            "pubkey": row[1],
            "meta": row[5],
            "version": row[6],
        })
    return users

def generate_user_id():
    while True:
        user_id = str(uuid.uuid4())
        conn = sqlite3.connect(server_db_file, timeout = 30000)
        curr = conn.cursor()
        curr.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
        row = curr.fetchone()
        conn.close()
        if not row:
            return user_id

def get_user_id_from_username(username):
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()
    curr.execute("SELECT user_id FROM users WHERE username = ?", (username,))
    row = curr.fetchone()
    conn.close()
    if row:
        return row[0]
    return None

def get_all_usernames():
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr= conn.cursor()
    #not sure why ASC needs to be specified for it to work properly
    curr.execute("SELECT username FROM users ORDER BY username ASC")
    rows = curr.fetchall()
    conn.close()
    #returns as list rather than as tuple with just return rows
    return [row[0] for row in rows]

def request_privkey(user_id, pake_password):
    conn = sqlite3.connect(server_db_file, timeout = 30000)
    curr = conn.cursor()
    curr.execute("SELECT pake_password, privkey_store FROM users WHERE user_id = ?", (user_id,))
    row = curr.fetchone()
    conn.close()
    if row:
        stored_pake_password, privkey_store = row
        if stored_pake_password == pake_password:
            return privkey_store
        else:
            return None
    return None

#just a basic testing function to check basic database functionality with user adding and fetching
def test_db():
    print("Running database test")
    init_db()
    #can just change userid so that it makes new users rather than updating the same one
    test_user_id = "user665"
    test_username = "ALICE"
    pubkey = "fake_pubkey_111"
    privkey_store = "fake_privkey_112"
    pake_password = "securepassword"
    meta = {"nickname": "Alice", "role": "user"}

    #change this serverid each run to add new entry
    test_server_id = "server_111111"
    host = "123.456.789"
    port = 50
    serverpubkey = "fakepubkey_also_1"

    print("test adding user")
    update_user(test_user_id, pubkey, privkey_store, test_username, pake_password, meta, version=1)

    print("trying to fetch userdata")
    user_data = get_user(test_user_id)
    print("Retrieved userdata: ", user_data)

    notrealuser = get_user("not_added_user")
    print("Non-existent user:", notrealuser)

    #server section
    print("trying to add server")
    update_server(test_server_id, host, port, serverpubkey)
    
    print("trying to fetch serverdata")
    server_data = get_server(test_server_id)
    print("Retrieved serverdata:", server_data)

    #try to list all servers
    print("printing all servers:", list_servers())
    print(get_all_usernames())

    #bulk testing, (user_id, pubkey, privkey_store, username, pake_password, meta, version)
    bulk_users = [("userid_bulk1", "pubkey1", "privkey1", "Joe", "PassSalted1", {"nickname": "toe"}, 1),
    ("userid_bulk2", "pubkey2", "privkey2", "Man", "PassSalted2", {"nickname": "Bigman"}, 1),
    ("userid_bulk3", "pubkey3", "privkey3", "Jose", "PassSalted2", {"nickname": "jo"}, 1)
    
    ]
    update_user_bulk(bulk_users)
    print("Retrieving user data:", get_user("userid_bulk2"))
    print("All usernames:", get_all_usernames())

    #try pubkey fetch from userID
    print("Retrieving pubkey", get_pubkey_from_id("userid_bulk1"))

async def user_advertise_catch_up(user_id):
    # Function to catch up a new user on all of the already existing users on the network

    # Get the websocket of the user
    new_user_ws = local_users[user_id]

    for other_user_id, other_user_loc in list(user_locations.items()):
        # Skip self
        if other_user_id != user_id:
            if other_user_loc == 'local':
                # Local user
                other_user_server_id = server_id
            else:
                # remote user
                other_user_server_id = other_user_loc
            message = {
                "type": "USER_ADVERTISE",
                "from": server_id,
                "to": user_id, # Send to the new user only
                "ts": int(time.time() * 1000),
                "payload": {
                    "user_id": other_user_id,
                    "server_id": other_user_server_id,    # not needed on client (and not stored in db)
                    "meta": user_meta[other_user_id],
                    "pubkey": user_pubkey[other_user_id],
                }
            }
            # Sign the message
            signed_message = sign_message(message)

            # Send the message through the new users websocket
            await new_user_ws.send(json.dumps(signed_message))



async def peer_connect(peer_addr, peer_id):
    try:
        async with websockets.connect(peer_addr) as websocket:
            print(f"Connected to peer server {peer_id} at {peer_addr}")
            servers[peer_id] = websocket

            # Then listen to any messages from said server
            async for message in websocket:
                # Just reusing main handler logic for incoming messages
                message_data = json.loads(message)
                print(f"Received message from {peer_id}: {message_data.get('type')}")
    except Exception as e:
        print(f"Failed to connect to peer server {peer_id} at {peer_addr}: {e}")

async def safe_send(ws, msg):
    try:
        await ws.send(msg)
        return True
    except websockets.ConnectionClosed:
        return False

async def handler(websocket):
    # This function handles incoming WebSocket connections; one for each client
    # Moved here for exception handling
    connected_id = None
    connection_type = None # Server or User
    try:
        # Process any login or register messages from the user
        async for message in websocket:
            message_data = json.loads(message)
            if message_data.get('type') == "USER_LOGIN":
                print("Processing USER_LOGIN message")
                payload = message_data.get('payload', {})
                username = payload.get('username')
                user_id = get_user_id_from_username(username)
                if user_id:
                    encrypted_privkey = request_privkey(user_id, payload.get('pake_password'))
                    if encrypted_privkey:
                        response = {
                                "type": "LOGIN_SUCCESS",
                                "from": server_id,
                                "to": user_id,
                                "ts": int(time.time() * 1000),
                                "payload": {
                                    "user_id": user_id,
                                    "encrypted_privkey": encrypted_privkey,
                                    "pubkey": get_user(user_id)['pubkey'],
                                    "meta": get_user(user_id)['meta']
                                }
                            }
                    else:
                        response = {
                                "type": "LOGIN_FAILURE",
                                "from": server_id,
                                "to": user_id,
                                "ts": int(time.time() * 1000),
                                "payload": {
                                    "error": "Password Incorrect"
                                }
                            }
                        
                    signed_response = sign_message(response)
                    await websocket.send(json.dumps(signed_response))
                else:
                    response = {
                            "type": "LOGIN_FAILURE",
                            "from": server_id,
                            "ts": int(time.time() * 1000),
                            "payload": {
                                "error": "Username Not Found"
                            }
                        }
                    signed_response = sign_message(response)
                    await websocket.send(json.dumps(signed_response))
                    
            elif message_data.get('type') == "USER_REGISTER":
                print("Processing USER_REGISTER message")
                payload = message_data.get('payload', {})
                username = payload.get('username')
                pake_password = payload.get('pake_password')
                pubkey = payload.get('pubkey')
                privkey = payload.get('privkey')
                meta = payload.get('meta', {})
                user_id = generate_user_id()
                try:
                    add_new_user(user_id, pubkey, privkey, username, pake_password, meta)
                    response = {
                            "type": "REGISTRATION_SUCCESS",
                            "from": server_id,
                            "to": user_id,
                            "ts": int(time.time() * 1000),
                            "payload": {
                                "user_id": user_id
                            }
                        }
                    signed_response = sign_message(response)
                    await websocket.send(json.dumps(signed_response))
                except sqlite3.IntegrityError: 
                    response = {
                            "type": "REGISTRATION_FAILURE",
                            "from": server_id,
                            "ts": int(time.time() * 1000),
                            "payload": {
                                "error": "Non Unique Username",
                            }
                        }
                    signed_response = sign_message(response)
                    await websocket.send(json.dumps(signed_response))
            else:
                # Not a login or register, so proceed to normal operation
                if message_data.get('type') == "SERVER_HELLO_JOIN":
                    connection_type = "server" # Mark this connection as a server
                    connected_id = message_data.get('from')
                    print(f"Received a join request from a new server: {connected_id}")

                    requested_id = connected_id

                    if requested_id in servers:
                        print(f"Server ID {requested_id} already in use. Assigning a new ID.")
                        assigned_id = str(uuid.uuid4())
                    else:
                        assigned_id = requested_id
                    
                    # Extract relevant field from client's request
                    payload = message_data.get('payload', {})
                    host = payload.get('host')
                    port = payload.get('port')
                    pubkey = payload.get('pubkey')

                    # Convert the pubkey back into a usable key object for verification
                    # Again, lot of help from "external sources"
                    try:
                        pem_data = base64.urlsafe_b64decode(pubkey + '==') # Add padding back for decoding
                        pubkey_obj = serialization.load_pem_public_key(pem_data)
                        # Store the public key object for this server
                        server_pubkeys[assigned_id] = pubkey_obj
                    except Exception as e:
                        print(f"Failed to load public key from server {connected_id}: {e}")
                        # Need to reject the connection if we can't verify their key -- will do 

                    # Build list of currently connected clients needed for the response
                    payload_server_list = []
                    for sid, addr in server_addrs.items():
                        payload_server_list.append({
                            "server_id": sid,
                            "host": addr[0],
                            "port": addr[1],
                            "pubkey": addr[2]
                        })

                    # Store the new server's connection and address
                    servers[assigned_id] = websocket
                    server_addrs[assigned_id] = (host, port, pubkey)

                    # If the message type is SERVER_HELLO_JOIN, respond with SERVER_WELCOME
                    response = {
                        "type": "SERVER_WELCOME",
                        "from": server_id,
                        "to": connected_id,
                        "ts": int(time.time() * 1000), # Unix timestamp in milliseconds
                        "payload": {"assigned_id": assigned_id,
                                    "clients": payload_server_list
                        },
                        "sig": "..." # Placeholder for a digital signature
                    }
                    signed_response = sign_message(response) # Sign the response message
                    await websocket.send(json.dumps(signed_response)) # Send the response back to the client as a JSON string

                elif message_data.get('type') == "USER_HELLO":
                    connection_type = "user"  # Mark this connection as a user
                    connected_id = message_data.get('from')
                    print(f"Received a greeting from a new user: {connected_id}")

                    # Register the user in the in-memory tables
                    payload = message_data.get("payload", {})
                    local_users[connected_id]   = websocket
                    user_locations[connected_id] = "local"  # hosted here
                    user_meta[connected_id]     = payload.get('meta', {})
                    user_pubkey[connected_id]   = payload.get('pubkey')

                    # broadcast presence (USER_ADVERTISE)
                    response = {
                        "type": "USER_ADVERTISE",
                        "from": server_id,
                        "to": "*",  # Broadcast to all known servers
                        "ts": int(time.time() * 1000),
                        "payload": {
                            "user_id": connected_id,
                            "server_id": server_id,
                            "meta": user_meta[connected_id],
                            "pubkey": user_pubkey[connected_id],
                        }
                    }
                    # Broadcast the announcement to all connected servers
                    signed_advertise = sign_message(response)

                    # to peer servers
                    for peer_id, ws in list(servers.items()):
                        ok = await safe_send(ws, json.dumps(signed_advertise))
                        if not ok:
                            print(f"Pruning stale server {peer_id}")
                            servers.pop(peer_id, None)
                            server_addrs.pop(peer_id, None)
                            server_pubkeys.pop(peer_id, None)
                        #await ws.send(json.dumps(signed_advertise))
                    # broadcast to all local users as well
                    for uid, ws in list(local_users.items()):
                        ok = await safe_send(ws, json.dumps(signed_advertise))
                        if not ok:
                            print(f"Pruning stale user {uid}")
                            local_users.pop(uid, None)
                            user_locations.pop(uid, None)
                            user_meta.pop(uid, None)
                            user_pubkey.pop(uid, None)


                    # Catch the new user up on all the existing users
                    await user_advertise_catch_up(connected_id)

                else:
                    print(f"Received an unknown message type: {message_data.get('type')}")
                    # For any other message type, respond with SERVER_ERROR
                    response = {
                        "type": "ERROR",
                        "from": server_id,
                        "to": connected_id,
                        "ts": int(time.time() * 1000),
                        "payload": {
                            "code": "UNKNOWN_TYPE",
                            "detail": f"Message type {message_data.get('type')} is not recognised."
                        }
                    }
                    signed_response = sign_message(response)
                    await websocket.send(json.dumps(signed_response))
                    return # Close the connection after sending the error
                break
                

        # Keep the connection open to listen for further messages -- essentially the server's main loop after handshake
        async for message in websocket:
            message_data = json.loads(message)

            # If this is a server connection, verify the signature of incoming messages
            if connection_type == "server":
                if not await verify_signature(message_data):
                    print(f"Invalid signature from server {connected_id}, ignoring message")
                    continue # Ignore messages with invalid signatures

            print(f"Received message from {connected_id}: {message_data.get('type')}")

            # Logic to handle MSG_DIRECT
            if message_data.get('type') == "MSG_DIRECT":
                recipient_id = message_data.get('to') # Need to route message to correct recipient
                sender_id = message_data.get('from')
                _payload = message_data.get('payload', {})
                # Check if recipient is a local (on of our) users
                if user_locations.get(recipient_id) == "local":
                    recipient_ws = local_users.get(recipient_id)

                    response = {
                        "type": "USER_DELIVER",
                        "from": server_id,
                        "to": recipient_id,
                        "ts": message_data.get('ts'),
                        "payload": {
                            "ciphertext": _payload.get('ciphertext'),
                            "sender": sender_id,
                            "sender_pub": _payload.get('sender_pub'),
                            "content_sig": _payload.get('content_sig'),
                        }
                    }
                    signed_response = sign_message(response)
                    await recipient_ws.send(json.dumps(signed_response))
                else: # Recipient is not local, check if we know their location
                    destination_server = user_locations.get(recipient_id)
                    if destination_server and destination_server in servers:
                        # Connect to the destination server and forward the message
                        destination_ws = servers[destination_server]

                        response = {
                            "type": "SERVER_DELIVER",
                            "from": server_id,
                            "to": destination_server,
                            "ts": message_data.get('ts'),
                            "payload": {
                                "user_id": recipient_id,
                                "ciphertext": _payload.get('ciphertext'),
                                "sender": sender_id,
                                "sender_pub": _payload.get('sender_pub'),
                                "content_sig": _payload.get('content_sig'),
                            }
                        }
                        signed_response = sign_message(response)
                        await destination_ws.send(json.dumps(signed_response))
                    else:
                        print(f"Unknown recipient {recipient_id}, cannot deliver message")
                        # Send standard error response with USER_NOT_FOUND code as per SOCP
                        response = {
                            "type": "ERROR",
                            "from": server_id,
                            "to": sender_id,
                            "ts": int(time.time() * 1000),
                            "payload": {
                                "code": "USER_NOT_FOUND",
                                "detail": f"User {recipient_id} is not online or not registered."
                            }
                        }
                        signed_response = sign_message(response)
                        await websocket.send(json.dumps(signed_response))

            elif message_data.get('type') == "USER_ADVERTISE":
                # Announcement from another server about a user
                payload = message_data.get('payload', {})
                user_id = payload.get('user_id')
                server_of_user = payload.get('server_id')
                meta = payload.get('meta', {})
                pubkey = payload.get('pubkey')

                if user_id and server_of_user:
                    print(f"Received advertisement for user {user_id} on server {server_of_user}")
                    user_locations[user_id] = server_of_user # Update our mapping of user locations
                    user_meta[user_id] = meta
                    user_pubkey[user_id] = pubkey


            elif message_data.get('type') == "USER_REMOVE":
                # Announce from another server that a user has disconnected
                payload = message_data.get('payload', {})
                user_id = payload.get('user_id')
                server_of_user = payload.get('server_id')

                # Protocol says we should only remove if the server_id matches
                if user_locations.get(user_id) == server_of_user:
                    if user_id in user_locations:
                        del user_locations[user_id]
                        del user_meta[user_id]
                        del user_pubkey[user_id]
                        print(f"User {user_id} removed from locations table")

            elif message_data.get('type') == "SERVER_ANNOUNCE":
                print(f"Received server announcement from {connected_id}")
                # As per protocol, need to register the new server
                peer_id = message_data.get('from')
                payload = message_data.get('payload', {})
                host = payload.get('host')
                port = payload.get('port')
                pubkey = payload.get('pubkey')

                # Establish a connection ... will also initiate WebSocket connection back to them
                if peer_id and host and port and pubkey:
                    server_addrs[peer_id] = (host, port, pubkey)
                    # Copy + paste from above - storing it's public key for future verification
                    try:
                        pem_data = base64.urlsafe_b64decode(pubkey + '==') 
                        pubkey_obj = serialization.load_pem_public_key(pem_data)
                        server_pubkeys[peer_id] = pubkey_obj
                        
                        # Now that server's registered, we need a persistent connection to it
                        peer_addr = f"ws://{host}:{port}"
                        asyncio.create_task(peer_connect(peer_addr, peer_id))
                    except Exception as e:
                        print(f"Failed to load public key from SERVER_ANNOUNCE: {e}")

            elif message_data.get('type') == "FILE_START":
                recipient_id = message_data.get('to') # Need to files message to correct recipient
                sender_id = message_data.get('from')
                _payload = message_data.get('payload', {})
                # Check if recipient is a local (on of our) users
                if user_locations.get(recipient_id) == "local":
                    recipient_ws = local_users.get(recipient_id)

                    _payload["sender"] = sender_id
                    response = {
                        "type": "FILE_START",
                        "from": server_id,
                        "to": recipient_id,
                        "ts": message_data.get('ts'),
                        "payload": _payload
                    }
                    signed_response = sign_message(response)
                    await recipient_ws.send(json.dumps(signed_response))
                else: # Recipient is not local, check if we know their location
                    destination_server = user_locations.get(recipient_id)
                    if destination_server and destination_server in servers:
                        # Connect to the destination server and forward the message
                        # destination_ws = servers[destination_server]

                        # response = {
                        #     "type": "SERVER_DELIVER",
                        #     "from": server_id,
                        #     "to": destination_server,
                        #     "ts": message_data.get('ts'),
                        #     "payload": {
                        #         "user_id": recipient_id,
                        #         "ciphertext": _payload.get('ciphertext'),
                        #         "sender": sender_id,
                        #         "sender_pub": _payload.get('sender_pub'),
                        #         "content_sig": _payload.get('content_sig'),
                        #     }
                        # }
                        # signed_response = sign_message(response)
                        # await destination_ws.send(json.dumps(signed_response))
                        print(f"This server does not support forwarding files to remote users")
                    else:
                        print(f"Unknown recipient {recipient_id}, cannot deliver message")
                        # Send standard error response with USER_NOT_FOUND code as per SOCP
                        response = {
                            "type": "ERROR",
                            "from": server_id,
                            "to": sender_id,
                            "ts": int(time.time() * 1000),
                            "payload": {
                                "code": "USER_NOT_FOUND",
                                "detail": f"User {recipient_id} is not online or not registered."
                            }
                        }
                        signed_response = sign_message(response)
                        await websocket.send(json.dumps(signed_response))
            
            elif message_data.get('type') == "FILE_CHUNK":
                recipient_id = message_data.get('to') # Need to files message to correct recipient
                sender_id = message_data.get('from')
                _payload = message_data.get('payload', {})
                # Check if recipient is a local (on of our) users
                if user_locations.get(recipient_id) == "local":
                    recipient_ws = local_users.get(recipient_id)

                    _payload["sender"] = sender_id
                    response = {
                        "type": "FILE_CHUNK",
                        "from": server_id,
                        "to": recipient_id,
                        "ts": message_data.get('ts'),
                        "payload": _payload
                    }
                    signed_response = sign_message(response)
                    await recipient_ws.send(json.dumps(signed_response))
                else: # Recipient is not local, check if we know their location
                    destination_server = user_locations.get(recipient_id)
                    if destination_server and destination_server in servers:
                        # Connect to the destination server and forward the message
                        # destination_ws = servers[destination_server]

                        # response = {
                        #     "type": "SERVER_DELIVER",
                        #     "from": server_id,
                        #     "to": destination_server,
                        #     "ts": message_data.get('ts'),
                        #     "payload": {
                        #         "user_id": recipient_id,
                        #         "ciphertext": _payload.get('ciphertext'),
                        #         "sender": sender_id,
                        #         "sender_pub": _payload.get('sender_pub'),
                        #         "content_sig": _payload.get('content_sig'),
                        #     }
                        # }
                        # signed_response = sign_message(response)
                        # await destination_ws.send(json.dumps(signed_response))
                        print(f"This server does not support forwarding files to remote users")
                    else:
                        print(f"Unknown recipient {recipient_id}, cannot deliver message")
                        # Send standard error response with USER_NOT_FOUND code as per SOCP
                        response = {
                            "type": "ERROR",
                            "from": server_id,
                            "to": sender_id,
                            "ts": int(time.time() * 1000),
                            "payload": {
                                "code": "USER_NOT_FOUND",
                                "detail": f"User {recipient_id} is not online or not registered."
                            }
                        }
                        signed_response = sign_message(response)
                        await websocket.send(json.dumps(signed_response))

            elif message_data.get('type') == "FILE_END":
                recipient_id = message_data.get('to') # Need to files message to correct recipient
                sender_id = message_data.get('from')
                _payload = message_data.get('payload', {})
                # Check if recipient is a local (on of our) users
                if user_locations.get(recipient_id) == "local":
                    recipient_ws = local_users.get(recipient_id)

                    _payload["sender"] = sender_id
                    response = {
                        "type": "FILE_END",
                        "from": server_id,
                        "to": recipient_id,
                        "ts": message_data.get('ts'),
                        "payload": _payload
                    }
                    signed_response = sign_message(response)
                    await recipient_ws.send(json.dumps(signed_response))
                else: # Recipient is not local, check if we know their location
                    destination_server = user_locations.get(recipient_id)
                    if destination_server and destination_server in servers:
                        # Connect to the destination server and forward the message
                        # destination_ws = servers[destination_server]

                        # response = {
                        #     "type": "SERVER_DELIVER",
                        #     "from": server_id,
                        #     "to": destination_server,
                        #     "ts": message_data.get('ts'),
                        #     "payload": {
                        #         "user_id": recipient_id,
                        #         "ciphertext": _payload.get('ciphertext'),
                        #         "sender": sender_id,
                        #         "sender_pub": _payload.get('sender_pub'),
                        #         "content_sig": _payload.get('content_sig'),
                        #     }
                        # }
                        # signed_response = sign_message(response)
                        # await destination_ws.send(json.dumps(signed_response))
                        print(f"This server does not support forwarding files to remote users")
                    else:
                        print(f"Unknown recipient {recipient_id}, cannot deliver message")
                        # Send standard error response with USER_NOT_FOUND code as per SOCP
                        response = {
                            "type": "ERROR",
                            "from": server_id,
                            "to": sender_id,
                            "ts": int(time.time() * 1000),
                            "payload": {
                                "code": "USER_NOT_FOUND",
                                "detail": f"User {recipient_id} is not online or not registered."
                            }
                        }
                        signed_response = sign_message(response)
                        await websocket.send(json.dumps(signed_response))

                        
            
            # async for message in websocket:  (after USER_LOGIN/REGISTER/HELLO handling)
            elif message_data.get('type') == "MSG_PUBLIC_CHANNEL":
                # Public chat is plaintext transport, signed at the server envelope level.
                ts        = message_data.get("ts")
                payload   = message_data.get("payload", {}) or {}
                sender_id = message_data.get("from")

                # Deliver to all local users EXCEPT the sender (avoid echo).
                for uid, ws in list(local_users.items()):
                    if uid == sender_id:
                        continue
                    out = {
                        "type": "MSG_PUBLIC_CHANNEL",
                        "from": server_id,   # this server is the transport sender
                        "to": uid,
                        "ts": ts,
                        "payload": {
                            "message": payload.get("message"),
                            "sender":  sender_id
                        }
                    }
                    await safe_send(ws, json.dumps(sign_message(out)))

                # Only the origin server forwards to peer servers.
                # If this frame arrived from a peer server, do NOT re-broadcast (prevents loops).
                if connection_type == "user":
                    for sid, ws in list(servers.items()):
                        out_srv = {
                            "type": "MSG_PUBLIC_CHANNEL",
                            "from": server_id,
                            "to": "*",
                            "ts": ts,
                            "payload": {
                                "message": payload.get("message"),
                                "sender":  sender_id
                            }
                        }
                        await safe_send(ws, json.dumps(sign_message(out_srv)))


    except websockets.ConnectionClosed:
        print(f"Client {connected_id} disconnected")
        if connection_type == "server" and connected_id in servers:
            del servers[connected_id]
            del server_addrs[connected_id] 
            if connected_id in server_pubkeys:
                del server_pubkeys[connected_id]
        elif connection_type == "user" and connected_id in local_users:
            del local_users[connected_id]
            del user_locations[connected_id]
            del user_meta[connected_id]
            del user_pubkey[connected_id]

            # Need to broadcast USER_REMOVE to all connected servers
            message = {
                "type": "USER_REMOVE",
                "from": server_id,
                "to": "*", 
                "ts": int(time.time() * 1000),
                "payload": {
                    "user_id": connected_id,
                    "server_id": server_id
                }
            }
            signed_remove = sign_message(message)
            for ws in servers.values():
                await ws.send(json.dumps(signed_remove))

            # Also broadcast to all local clients
            for uid, ws in list(local_users.items()):
                ok = await safe_send(ws, json.dumps(signed_remove))
                if not ok:
                    print(f"Pruning stale user {uid}")
                    local_users.pop(uid, None)
                    user_locations.pop(uid, None)
                    user_meta.pop(uid, None)
                    user_pubkey.pop(uid, None)


    except json.JSONDecodeError:
        print("Received invalid JSON")


async def main():
    # Starts a WebSocket server on localhost:12345
    # For every new connection, 'handler' function is called
    async with websockets.serve(handler, 'localhost', 12345,
                                ping_interval=15, ping_timeout=30):
        print("Server started on ws://localhost:12345")
        await asyncio.Future() # run forever

if __name__ == "__main__":
    #create database if not already created
    init_db()

    #runs the db check if it is not a comment
    #test_db()
    asyncio.run(main())
