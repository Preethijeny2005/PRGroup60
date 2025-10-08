# ChatSystem

**Chat System Project for Secure Programming**
This repository contains our group's (Group 60) implementation of the Secure Overlay Chat Protocol (SOCP), a decentralised, end-to-end encrypted chat system, for the Advanced Secure Progamming assignment. 

**Project Overview**
This system is a decentralised, n-to-n mesh of servers that communicate using the Secure Overlay Chat Protocol that was (somewhat) agreed upon as a cohort. Users can connect to any server in the network, which becomes their "Local Server". 

Key architectural features include:
- **Transport**: All communication, for both server-to-server and client-to-server, is conducted extensively over WebSockets.
- **Messaging Format**: Every message is a single JSON object that conforms to the mandatory JSON Envelope structure defined in the SOCP document. 
- **Routing**: The system uses a "Presence Gossip" protocol. When a user connects, their Local Server advertises their presence to all other servers. This allows each server to maintain a complete *user_locations* directory to correctly route messages to any user on the network. 
- **Security**: All server-to-server communication is authenticated using digital signatures ("sig" field), which are generated and verified using RSA-4096 with RSASSA-PSS. Direct messages between users are end-to-end encrypted using RSA-4096 with RSA-OAEP. The server only routes the encrypted payloads and cannot read the content of private messages.

**Group Members & Contact**
- Sean Priestley, a1825197@adelaide.edu.au
- Lucas Caruso, a1788462@adelaide.edu.au
- Timothy Szabo, a1852299@adelaide.edu.au
- Hok Lam Lo, a1822027@adelaide.edu.au
- Aidan Ong a1844572@adelaide.edu.au

**Running the Application**
**IMPORTANT:** You **MUST** run this code inside the provided Docker container.

**1. Start the Backend Server:**
   In *Terminal 1*, run the Python server:

   ```python server.py```

**2. Start the Frontend UI:**
   In *Terminal 2*, run the web server for the user interface:

   ```npm start```

**3. Access the Chat:**
   Once both components are running, open your web browser and navigate to:
   
   ```http://localhost:3000```

As mentioned, the code **MUST** be run inside the provided Docker container as it includes all the necessary Python and Node.js dependencies, removing the need to install them manually.