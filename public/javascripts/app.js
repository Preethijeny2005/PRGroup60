const { createApp } = Vue;

createApp({
  data() {
    return {
      page: 'login',
      logged_in: false,
      user_id: null,    // User UUID
      server_id: null,  // Local server UUID
      public_key: null,
      spki: null,
      private_key: null,
      signing_private_key: null,  // for signatures
      pkcs8: null,
      username: '',
      display_name: '',
      meta: {},
      password: '',
      draft: '',
      register_state: 'none',
      selectedChat: 'Public',
      chats: ['Public', 'Alice', 'Bob'],
      showUserPicker: true,
      selectedFile: null,
      files: {},
      users: {
        Public: {
          public_key: null,
          signing_pubkey: null,
          meta: { display_name: "Public" },
          messages: [],
          server: "local",
          active_chat: true,
          status: "online",
          online: true,
          unread_count: 0,
        },
      },
      outbox: [],
      // Websocket stuff
      ws: null,
      shouldReconnect: true,
      reconnectDelay: 500, // ms
      reconnectTimer: null,
      websocket_urls: ["ws://localhost:12345", "ws://fallback:11111"],
    };
  },
  created() {
    this.open_websocket();
  },
  methods: {
    open_websocket() {
      if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return;

      const url = this.websocket_urls[0];
      this.ws = new WebSocket(url);

      this.ws.addEventListener('open', () => {
        console.log('WS OPEN');
        this.reconnectDelay = 500;          // reset backoff
        if (this.logged_in && this.user_id && this.server_id) {
          this.send_user_hello();           // <-- send only here
        }
      });

      this.ws.addEventListener('message', async ev => {
        try { await this.handle_message(JSON.parse(ev.data)); }
        catch (e) { console.warn('Bad JSON', e); }
      });

      this.ws.addEventListener('close', e => {
        console.warn('WS closed', e.code, e.reason);
        this.ws = null;
        if (!this.shouldReconnect) return;
        //if (e.code === 1000 || e.code === 1001) return; // normal/going away → no auto-reconnect
        this.scheduleReconnect();
      });

      this.ws.addEventListener('error', e => {
        console.error('ws error', e);
      });
    },

    scheduleReconnect() {
      clearTimeout(this.reconnectTimer);
      const delay = Math.min(this.reconnectDelay, 10000);
      this.reconnectTimer = setTimeout(() => this.open_websocket(), delay);
      this.reconnectDelay *= 2;
    },
    async handle_message(msg) {
      console.log(msg);
      console.log("Handling incoming message, type: " + msg['type']);
      const msg_type = msg['type'];
      switch (msg_type) {
        case "LOGIN_FAILURE":
          this.handle_login_failure(msg);
          break;
        case "LOGIN_SUCCESS":
          this.handle_login_success(msg);
          break;
        case "REGISTRATION_SUCCESS":
          this.handle_register_success(msg);
          break;
        case "REGISTRATION_FAILURE":
          this.handle_register_fail(msg);
          break;
        case "USER_ADVERTISE":
          await this.handle_user_advertise(msg);
          break;
        case "USER_DELIVER":
          await this.handle_user_deliver(msg);
          break;
        case "FILE_START":
          await this.handle_file_start(msg);
          break;
        case "FILE_CHUNK":
          await this.handle_file_chunk(msg);
          break;
        case "FILE_END":
          await this.handle_file_end(msg);
          break;
        case "USER_REMOVE":
          this.handle_user_remove(msg);
          break;
        case "MSG_PUBLIC_CHANNEL":
          await this.handle_msg_public_channel(msg);
          break;

        default:
          console.log("Unkown message type, ignoring");
          break;
      }
    },
    async handle_user_deliver(msg) {
      // verify signature
      const sig_status = await this.verify_signature(msg)

      if (!sig_status) {
        // Signature incorrect
        console.log("Bad signature!");
        return;
      } else {
        console.log("Good signature")
      }

      // Extract message fields
      const payload = msg['payload'];
      const timestamp = msg['ts'];
      const sender = payload["sender"];
      const encrypted_message = payload["ciphertext"]
      const sender_pub_key = payload["sender_pub"]    // TODO: replace with trusted source

      // TODO: check the included public key matches the one sent with user advertise

      // Decrypt the message
      const decrypted_message = await decryptString(encrypted_message, this.private_key);

      // Check the user is known to the client
      if (sender in this.users) {
        // sender is known, proceed
        message_data = { type: 'text', sender: sender, message: decrypted_message, timestamp: new Date(timestamp).toLocaleString() }
        this.users[sender]['messages'].push(message_data);
        this.users[sender]['active_chat'] = true;
        this.users[sender]['unread_count'] = this.users[sender]['unread_count'] + 1;
      } else {
        // sender unknown,discard message
        console.warn("Message recieved from unknown sender, discarding")
        return;
      }

    },
    async handle_file_start(msg) {
      const fileID = msg['payload']['file_id'];

      const file_data = {
        name: msg['payload']['name'],
        size: msg['payload']['size'],
        sha256: msg['payload']['sha256'],
        index: 0,
        chunks: [],
        decrypting: [],
        file: null,
      };

      this.files[fileID] = file_data;
    },
    async handle_file_chunk(msg) {
      const fileID = msg['payload']['file_id'];
      const chunkIdx = msg['payload']['index'];
      const encryptedChunk = msg['payload']['ciphertext'];

      const decryptPromise = decryptString(encryptedChunk, this.private_key)
      .then(decryptedChunk => {
        const binChunk = fromB64u(decryptedChunk);
        this.files[fileID].chunks[chunkIdx] = binChunk;
        this.files[fileID].index++;
      });

      this.files[fileID].decrypting.push(decryptPromise);
    },
    async handle_file_end(msg) {
      console.log("Handle file end");
      
      const sender_id = msg['payload']['sender'];
      const fileID = msg['payload']['file_id'];

      await Promise.all(this.files[fileID].decrypting);

      const arrayBuffer = await this.joinChunks(this.files[fileID].chunks);
      const blob = new Blob([arrayBuffer]);
      this.files[fileID].file = blob;
      // console.log("Chunks recieved:", this.files[fileID].index);
      // console.log("First Chunk Size:", this.files[fileID].chunks[0].byteLength || chunk.length);
      // console.log("File received:", blob.name, blob.size, "bytes");
      // Update locally
      this.users[sender_id]['messages'].push({
        type: "file",
        sender: sender_id,
        filename: this.files[fileID]['name'],
        filesize: this.files[fileID]['file'].size,   // Filesize (Bytes) TODO
        url: URL.createObjectURL(this.files[fileID]['file']),
        timestamp: new Date(Number(timestamp)).toLocaleString(),
      });
    },
    async joinChunks(chunks) {
      // Convert all to Uint8Array views
      const uint8Arrays = chunks.map(chunk => 
        chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)
      );

      // Get total size
      const totalLength = uint8Arrays.reduce((sum, arr) => sum + arr.length, 0);

      // Create a big array
      const joined = new Uint8Array(totalLength);

      // Copy each chunk into the combined buffer
      let offset = 0;
      for (const arr of uint8Arrays) {
        joined.set(arr, offset);
        offset += arr.length;
      }

      return joined.buffer; // return as ArrayBuffer
    },
    async handle_user_advertise(msg) {
      if (msg['payload']['user_id'] == this.user_id) {
        // skip self
        return;
      }
      // TODO: verify sig
      const id_to_add = msg['payload']['user_id'];
      // Check if the user already exists in array
      if (this.users[id_to_add]) {
        // already exists, update status to online
        this.users[id_to_add]['online'] = true;
      } else {
        // new user
        // Add to users array
        const pubkey = await importRsaOaepPublicKey(fromB64u(msg['payload']['pubkey']));
        const signing_pubkey = await importRsaPssPublicKey(fromB64u(msg['payload']['pubkey']));
        user_data = {
          public_key: pubkey,
          signing_pubkey: signing_pubkey,
          meta: msg['payload']['meta'],
          messages: [],
          server: msg['payload']['server_id'],
          active_chat: false,
          online: true,
          unread_count: 0,
        }
        this.users[id_to_add] = user_data;
      }


    },
    handle_user_remove(msg) {
      // TODO: verify signature
      const id_to_remove = msg['payload']['user_id'];

      if (this.users.get[id_to_remove]) {
        // Exists in users list
        if (this.users[id_to_remove]['active_chat'] == false) {
          // Simply remove the user
          delete this.users[id_to_remove]

        } else {
          // Active chat, so simply update status to online
          this.users[id_to_remove]['online'] = false;
        }
      }
    },
    handle_login_failure(msg) {

    },
    async handle_login_success(msg) {
      const payload = msg['payload'];
      this.user_id = payload['user_id'];
      this.server_id = msg['from'];
      this.spki = fromB64u(payload['pubkey']);
      this.meta = payload['meta'];

      // base64url decode password (async)
      const encBuf = fromB64u(payload['encrypted_privkey']);
      // returns the clear private key
      this.pkcs8 = await decrypt_private_key(encBuf, this.password);

      // Import keys
      this.public_key = await importRsaOaepPublicKey(this.spki);
      this.private_key = await importRsaOaepPrivateKey(this.pkcs8);
      this.signing_private_key = await importRsaPssPrivateKey(this.pkcs8);

      console.log("Opening a new web socket");
      try { this.ws && this.ws.close(); } catch { }
      this.open_websocket();

      this.send_user_hello();
      this.logged_in = true;
      this.page = 'chats';
    },

    handle_register_success(msg) {
      // Navigate to the log in screen
      this.page = 'login';
    },
    handle_register_fail(msg) {
      this.register_state = 'failed'
    },
    send_json_object(obj) {
      console.log("sending json object", obj)
      const s = this.ws;
      if (!s) { console.warn('WS missing; not sending', obj.type); return; }

      const msg = JSON.stringify(obj);
      switch (s.readyState) {
        case WebSocket.OPEN:       // 1
          try { s.send(msg); } catch (e) { console.error('WS send failed', e); }
          break;

        case WebSocket.CONNECTING: // 0
          this.outbox.push(msg);
          const flushOnce = () => {
            s.removeEventListener('open', flushOnce);
            this.flushOutbox();
          };
          s.addEventListener('open', flushOnce);
          break;

        case WebSocket.CLOSING:    // 2
        case WebSocket.CLOSED:     // 3
        default:
          console.warn('WS not open (state:', s.readyState, '); queued', obj.type);
          this.outbox.push(msg);
          break;
      }
    },

    flushOutbox() {
      const s = this.ws;
      if (!s || s.readyState !== WebSocket.OPEN) return;
      while (this.outbox.length) {
        try { s.send(this.outbox.shift()); } catch (e) { console.error('WS flush failed', e); break; }
      }
    },
    send_user_hello() {
      console.log("sending user hello")
      // Get the current time
      timestamp = Date.now();
      user_hello_json = {
        type: "USER_HELLO",
        from: this.user_id,
        to: this.server_id,
        ts: timestamp,
        payload: {
          client: "web-gui-v1",
          pubkey: toB64u(this.spki),
          enc_pubkey: toB64u(this.spki),    // TODO: check whether this should be different
          meta: this.meta
        },
        sig: "", // optional on first frame
      }
      // TODO: add signature here
      this.send_json_object(user_hello_json);
    },
    async sendMessage() {
      // Send text and file separately
      const recipient = this.selectedChat;
      const message_content = this.draft;
      this.draft = "";
      // Text
      // --- Public channel path ---
      if (recipient === 'Public' && message_content != "") {
        const ts = Date.now();
        const frame = {
          type: "MSG_PUBLIC_CHANNEL",
          from: this.user_id,
          to:   "public",
          ts:   ts,
          payload: {
            // plaintext
            message: message_content
          },
          sig: ""
        };
        await this.sign_message(frame);
        this.send_json_object(frame);

        this.users.Public.messages.push({
          type: 'text',
          sender: this.user_id,
          message: message_content,
          timestamp: new Date(ts).toLocaleString(),
        });
        return;
      }
      // --- end public path ---
      
      if(message_content != ""){
        await this.send_direct_message(recipient, message_content);
      }

      // File
      const fileInput = document.getElementById("fileInput");
      if (fileInput.files.length === 0) {
        console.log("No file selected");
      } else {
        const file = fileInput.files[0]; // get first file
        // console.log("File selected:", file.name, file.size, "bytes");
        this.send_file_message(recipient, file)
      }
    },
    async send_direct_message(recipient_id, message) {
      // Generate the ciphertext of the message
      const ciphertext = await encryptString(message, this.users[recipient_id]['public_key'])

      // Get the current time
      const timestamp = Date.now();
      const dm_json = {
        type: "MSG_DIRECT",
        from: this.user_id,
        to: recipient_id,
        ts: timestamp,
        payload: {
          ciphertext: ciphertext,
          sender_pub: this.public_key,
        },
        sig: "",  // OPTIONAL. TODO: consider adding 
      }
      // Sign the message (content, not transport layer)
      await this.sign_message(dm_json);

      this.send_json_object(dm_json);

      // Update the UI
      this.users[recipient_id]['messages'].push({
        type: "text",
        sender: this.user_id,
        message: message,
        timestamp: new Date(Number(timestamp)).toLocaleString(),
      });
    },
    async handle_msg_public_channel(msg) {
      if (!this.users.Public) {
        this.users.Public = {
          public_key: null,
          signing_pubkey: null,
          meta: { display_name: "Public Channel" },
          messages: [],
          server: "local",
          active_chat: true,
          status: "online",
          online: true,
          unread_count: 0,
        };
      }

      const p = msg.payload || {};
      const sender = p.sender || msg.from || "(unknown)";
      const tsStr  = new Date(Number(msg.ts || Date.now())).toLocaleString();

      // plaintext only
      const text = (typeof p.message === "string") ? p.message : "";

      this.users.Public.messages.push({ type: 'text', sender, message: text, timestamp: tsStr });

      if (this.selectedChat !== "Public") {
        this.users.Public.unread_count = (this.users.Public.unread_count || 0) + 1;
      } else {
        this.$nextTick(() => {
          const chatDiv = document.querySelector(".chat-conversation");
          if (chatDiv) chatDiv.scrollTop = chatDiv.scrollHeight;
        });
      }
    },

    generate_message_ciphertext(message) {
      // TODO: encrypt
      return message;
    },
    async splitArrayBuffer(buffer, chunkSize = 256) {
      const chunks = [];
      const totalLength = buffer.byteLength;
      let offset = 0;

      while (offset < totalLength) {
        const end = Math.min(offset + chunkSize, totalLength);
        const chunk = buffer.slice(offset, end); // slice returns a new ArrayBuffer
        chunks.push(chunk);
        offset = end;
      }

      return chunks;
    },
    async send_file_message(recipient_id, file) {
      // Generate the ciphertext of the message
      const arrayBuffer = await file.arrayBuffer();

      // Compute SHA-256 digest
      const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);

      // Convert ArrayBuffer to hex string
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      // Split message into chunks
      const chunks = await this.splitArrayBuffer(arrayBuffer, 256);

      // Compute random UUID for the file
      const fileUUID = crypto.randomUUID();

      // send start msg
      let timestamp = Date.now();
      let file_json = {
        type: "FILE_START",
        from: this.user_id,
        to: recipient_id,
        ts: timestamp,
        payload: {
          file_id: fileUUID,
          name: file.name,
          size: chunks.length,
          sha256: hashHex,
          mode: "dm", //only implementing dm file share
        },
        sig: "",  // OPTIONAL. TODO: consider adding 
      }
      // Sign the message (content, not transport layer)
      await this.sign_message(file_json);
      this.send_json_object(file_json);

      // Update locally
      this.users[recipient_id]['messages'].push({
        type: "file",
        sender: this.user_id,
        filename: file.name,
        filesize: file.size,   // Filesize (Bytes) TODO
        url: URL.createObjectURL(file),
        timestamp: new Date(Number(timestamp)).toLocaleString(),
      });

      // send chunk msgs
      for (let i = 0; i < chunks.length; i++){
        const chunkString = toB64u(chunks[i]);
        const ciphertext = await encryptString(chunkString, this.users[recipient_id]['public_key']);
        timestamp = Date.now();
        file_json = {
          type: "FILE_CHUNK",
          from: this.user_id,
          to: recipient_id,
          ts: timestamp,
          payload: {
            file_id: fileUUID,
            index: i,
            ciphertext: ciphertext,
          },
          sig: "",  // OPTIONAL. TODO: consider adding 
      }
      // Sign the message (content, not transport layer)
      await this.sign_message(file_json);
      this.send_json_object(file_json);
      }

      // send end msg
      timestamp = Date.now();
      file_json = {
        type: "FILE_END",
        from: this.user_id,
        to: recipient_id,
        ts: timestamp,
        payload: {
          file_id: fileUUID,
        },
        sig: "",  // OPTIONAL. TODO: consider adding 
      }
      // Sign the message (content, not transport layer)
      await this.sign_message(file_json);
      this.send_json_object(file_json);

      // Update the UI
      // this.users[recipient_id]['messages'].push({
      //   sender: this.user_id,
      //   message: message,
      //   timestamp: new Date(Number(timestamp)).toLocaleString(),
      // });
    },
    async register() {
      // Password policy
      const { ok, reasons } = validatePassword(this.password);
      if (!ok) {
        this.register_state = 'failed';
        alert("Password requirements:\n- " + reasons.join("\n- "));
        return;
      }
      this.register_state = 'in_progress';

      // Generate RSA keypair
      const { publicKey, privateKey } = await generateRsa4096Oaep();
      const spki = await crypto.subtle.exportKey('spki', publicKey);
      const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);

      // Encrypt private key with password
      const encPrivBuf = await encrypt_private_key(pkcs8, this.password);
      const enc_privkey_b64u = toB64u(encPrivBuf);

      // PAKE verifier (SHA-256 b64url; make sure server matches)
      const pake_password = await sha256B64Url(this.password);

      const uname = this.username.trim();
      const dname = this.display_name.trim();
      const timestamp = Date.now();

      const register_message = {
        type: 'USER_REGISTER',
        from: "",
        to: "",
        ts: timestamp,
        payload: {
          username: uname,
          pake_password,
          pubkey: toB64u(spki),
          privkey: enc_privkey_b64u,
          meta: { display_name: dname }
        },
        // TODO: sign message
        sig: "",
      };

      this.send_json_object(register_message);
    },

    async login() {
      // presence check to avoid empty submissions
      if (!this.username || !this.password) {
        alert("Please enter username and password.");
        return;
      }

      const pake_password = await sha256B64Url(this.password);
      const timestamp = Date.now();
      const login_message = {
        type: 'USER_LOGIN',
        from: "",
        to: "",
        ts: timestamp,
        payload: {
          username: this.username.trim(),
          pake_password
        },
        sig: "",
      };
      this.send_json_object(login_message);
    },
    logout() {
      this.shouldReconnect = false;   // Don't reopen the web socket
      this.ws.close()
      this.page = 'login';
      this.username = '';
      this.password = '';
      // TODO: Check all other info is cleared too (public/private keys)
    },
    selectChat(chat) {
      if (this.users[chat]) this.users[chat].unread_count = 0;
      this.showUserPicker = false;
      this.selectedChat = chat;
    },
    openUserPicker() {
      console.log("Show user picker")
      this.showUserPicker = true;
    },
    closeUserPicker() {
      this.showUserPicker = false;
    },
    startChat(user_id) {
      this.users[user_id]['active_chat'] = true;
      this.selectedChat = user_id;
      this.showUserPicker = false;


    },
    label(user_id) {
      const u = this.users?.[user_id];

      if (!u) {
        return "(unknown user)";
      }

      if (u.meta && typeof u.meta.display_name === 'string' && u.meta.display_name.trim() !== "") {
        return u.meta.display_name;
      }

      return user_id || "(unknown user)";
    },
    async sign_message(msg) {
      const sk = this.signing_private_key;
      if (!sk) return msg;

      if (msg?.type === 'MSG_DIRECT') {
        const data = buildDirectSigInput(msg);
        const sigBuf = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, sk, data);
        msg.payload.content_sig = toB64u(sigBuf);
        return msg;
      }

      if (msg?.type === 'MSG_PUBLIC_CHANNEL') {
        const data = buildPublicSigInput(msg);
        const sigBuf = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, sk, data);
        // Put the content-level signature in payload per SOCP
        msg.payload.content_sig = toB64u(sigBuf);
        return msg;
      }

      console.warn(`addSignature: unsupported type ${msg?.type}; returning unsigned.`);
      return msg;
    },

    async verify_signature(msg) {
      // Retrieve the sender
      const sender_id = msg.payload.sender ?? undefined
      console.log(this.users[sender_id])
      // Retrieve the public key the message was signed with
      const signing_public_key = this.users[sender_id]['signing_pubkey'];
      console.log(signing_public_key)
      // Call the helper function
      const signature_correct = await verifySignature(msg, signing_public_key);

      // Return state
      return signature_correct;
    },
    updateFileSelection(event){
      console.log("Selected file: " + event.target.files[0])
      this.selectedFile = event.target.files[0];
    }
  }
}).mount('#app');

async function generateRsa4096Oaep() {
  return crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['encrypt', 'decrypt']
  );
}

/* ArrayBuffer → base64url (no padding).
 * in:  ArrayBuffer (e.g., DER from exportKey)
 * out: string using A–Z a–z 0–9 - _ (no '=') */
function toB64u(ab) {
  return btoa(String.fromCharCode(...new Uint8Array(ab)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* base64url (no padding) → ArrayBuffer.
 * in:  string using A–Z a–z 0–9 - _ (no '=')
 * out: ArrayBuffer (e.g., suitable for importKey or crypto use) */
function fromB64u(b64url) {
  const b64 = b64url
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(b64url.length + (4 - b64url.length % 4) % 4, '=');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Encrypts a plaintext string using RSA-OAEP(SHA-256) for messages.
 * 
 * @param {string} plaintext - The message to encrypt.
 * @param {CryptoKey} recipientPublicKey - The recipient’s RSA-OAEP public key.
 * @returns {Promise<string>} - Base64url-encoded ciphertext (no padding).
 */
async function encryptString(plaintext, recipientPublicKey) {
  const data = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    data
  );

  return toB64u(ciphertext);
}

/**
 * Decrypts a base64url-encoded ciphertext using RSA-OAEP(SHA-256).
 * 
 * @param {string} ciphertextB64u - The ciphertext in base64url format (no padding).
 * @param {CryptoKey} myPrivateKey - Your RSA-OAEP private key.
 * @returns {Promise<string>} - The decrypted plaintext string.
 */
async function decryptString(ciphertextB64u, myPrivateKey) {
  const ciphertextBuf = fromB64u(ciphertextB64u);

  const plaintextBuf = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    myPrivateKey,
    ciphertextBuf
  );

  // don't decrypt for now
  return new TextDecoder().decode(plaintextBuf);
}

// function encrypt_private_key(key, password){
//   // TODO: implement this
//   return key;
// }

// function decrypt_private_key(enc_key, password){
//   // TODO: implement this
//   return enc_key;
// }

// SPKI (public) → CryptoKey for RSA-OAEP(SHA-256)
async function importRsaOaepPublicKey(spkiArrayBuffer) {
  return crypto.subtle.importKey(
    'spki',
    spkiArrayBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,                   // extractable?
    ['encrypt']             // key usages
  );
}

// PKCS#8 (private) → CryptoKey for RSA-OAEP(SHA-256)
async function importRsaOaepPrivateKey(pkcs8ArrayBuffer) {
  return crypto.subtle.importKey(
    'pkcs8',
    pkcs8ArrayBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}


/**
 * verifySignature(msg, public_key)
 * - For MSG_DIRECT: verifies payload.content_sig using payload.sender_pub.
 * - Others: warns and returns true.
 * Returns: boolean
 */
async function verifySignature(msg, pubKey) {
  if (msg?.type === 'USER_DELIVER') {
    const content_sig = msg.payload?.content_sig ?? undefined;
    if (!content_sig) {
      console.log("No signature provided, failing signature check");
      return false;
    }

    const data = buildDirectSigInput(msg);
    const ok = await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      pubKey,
      fromB64u(content_sig),
      data
    );
    return !!ok;
  } else {
    console.warn(`verifySignature: unsupported type ${msg?.type}; assuming valid (true).`);
    return true;
  }
}

// Build sign/verify input for MSG_DIRECT: ciphertext || from || to || ts
// Note this is used for USER_DELIVER messages signature verification as well as constructing the signature for MSG_DIRECT
function buildDirectSigInput(msg) {
  var from_field = undefined;
  var to_field = undefined;
  var { ts } = msg ?? null;
  var { ciphertext } = msg.payload ?? undefined;

  if (msg.type == "USER_DELIVER") {
    from_field = msg['payload']['sender'];
    to_field = msg['to'];
  } else if (msg.type == "MSG_DIRECT") {
    from_field = msg['from'];
    to_field = msg['to'];
  }

  if (!ciphertext || !from_field || !to_field || ts == null) {
    throw new Error("MSG_DIRECT (or USER_DELIVER) missing required fields (ciphertext/from/to/ts).");
  }

  const fields = [
    new Uint8Array(fromB64u(ciphertext)),
    toUtf8Bytes(from_field),
    toUtf8Bytes(to_field),
    toUtf8Bytes(ts)
  ]

  const result = orBuffers(fields);
  return result
}

function buildPublicSigInput(msg) {
  const { from, ts } = msg;
  const p = msg.payload || {};
  const piece = p.ciphertext ? fromB64u(p.ciphertext) : new TextEncoder().encode(String(p.message ?? ""));
  const parts = [
    new Uint8Array(piece),
    toUtf8Bytes(from),
    toUtf8Bytes(ts)
  ];
  return orBuffers(parts);
}


// Functions for doing the ORing
function padToLength(arr, len) {
  const out = new Uint8Array(len);
  out.set(arr.slice(0, len));
  return out;
}

function toUtf8Bytes(str) {
  return new TextEncoder().encode(String(str));
}

function orBuffers(buffers) {
  const len = Math.max(...buffers.map(b => b.length));
  const padded = buffers.map(b => padToLength(b, len));
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = padded.reduce((acc, b) => acc | b[i], 0);
  }
  return result;
}

// Import RSASSA-PSS public key (SPKI) for verification
async function importRsaPssPublicKey(spkiArrayBuffer) {
  return crypto.subtle.importKey(
    'spki',
    spkiArrayBuffer,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    true,                 // extractable?
    ['verify']            // key usages
  );
}

// Import RSASSA-PSS private key (PKCS8) for signing
async function importRsaPssPrivateKey(pkcs8ArrayBuffer) {
  return crypto.subtle.importKey(
    'pkcs8',
    pkcs8ArrayBuffer,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    true,                 // extractable?
    ['sign']              // key usages
  );
}

// === Password  ===

// Generate random bytes
function getRandomBytes(len) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

// password policy, force strong passwords
function validatePassword(pw) {
  const reasons = [];
  if (typeof pw !== 'string') reasons.push("Password missing.");
  if (!pw || pw.trim() !== pw) reasons.push("No leading/trailing spaces.");
  if (!pw || pw.length < 6) reasons.push("Minimum 12 characters.");
  if (!/[a-z]/.test(pw)) reasons.push("At least one lowercase letter.");
  if (!/[A-Z]/.test(pw)) reasons.push("At least one uppercase letter.");
  if (!/[0-9]/.test(pw)) reasons.push("At least one digit.");
  if (!/[^A-Za-z0-9]/.test(pw)) reasons.push("At least one symbol.");
  const banned = ["password", "123456", "qwerty", "letmein", "admin"];
  if (banned.includes(pw.toLowerCase())) reasons.push("Too common.");
  return { ok: reasons.length === 0, reasons };
}

// Hash to base64url for PAKE verifier
async function sha256B64Url(s) {
  const data = new TextEncoder().encode(s);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return toB64u(hash);
}

// PBKDF2 key derivation
async function pbkdf2KeyFromPassword(password, salt, iterations = 200000) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Layout: [ salt(16) | iv(12) | ciphertext(...) ] base64url when serialised
async function encrypt_private_key(pkcs8Buf, password) {
  if (!(pkcs8Buf instanceof ArrayBuffer)) throw new Error("encrypt_private_key expects ArrayBuffer");
  const salt = getRandomBytes(16);
  const iv = getRandomBytes(12);
  const key = await pbkdf2KeyFromPassword(password, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pkcs8Buf);

  // salt|iv|ct to ArrayBuffer
  const uSalt = new Uint8Array(salt);
  const uIv = new Uint8Array(iv);
  const uCt = new Uint8Array(ct);
  const out = new Uint8Array(uSalt.length + uIv.length + uCt.length);
  out.set(uSalt, 0);
  out.set(uIv, uSalt.length);
  out.set(uCt, uSalt.length + uIv.length);
  return out.buffer; // ArrayBuffer
}

async function decrypt_private_key(encBuf, password) {
  if (!(encBuf instanceof ArrayBuffer)) throw new Error("decrypt_private_key expects ArrayBuffer");
  const u8 = new Uint8Array(encBuf);
  if (u8.length < 16 + 12 + 16) throw new Error("Encrypted blob too short");

  const salt = u8.slice(0, 16);
  const iv = u8.slice(16, 28);
  const ct = u8.slice(28);

  const key = await pbkdf2KeyFromPassword(password, salt);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return plain; // ArrayBuffer (PKCS#8)
}

function guessMime(name) {
  const ext = name.split('.').pop()?.toLowerCase();
  if (["png","jpg","jpeg","gif","webp","bmp"].includes(ext)) return `image/${ext==='jpg'?'jpeg':ext}`;
  if (ext==="pdf") return "application/pdf";
  if (["txt","log"].includes(ext)) return "text/plain";
  return "application/octet-stream";
}
