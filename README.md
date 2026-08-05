# 💬 Persian Chat Application (chat-app)

A lightweight, modern, and high-performance **Real-Time Persian Messenger** built using full-stack JavaScript. This project is specifically architected to support fluid, bidirectional communication with a seamless user experience tailored for Persian-speaking users.

---

## 🚀 How It Works

The **chat-app** follows a decoupled client-server architecture to provide persistent connections and instant messaging capabilities:
1. **Handshake & Connection**: When a user opens the client interface, a WebSocket handshake protocol is initiated with the Node.js server.
2. **Persistent Session**: Once verified, a persistent, bi-directional TCP connection is established via WebSockets.
3. **Event-Driven Delivery**: Messages are processed as asynchronous payloads. When User A sends a message, it triggers a server event which instantaneously broadcasts or selectively routes the message to User B's active socket session.
4. **Fallback Mechanism**: If the client's network environment restricts native WebSockets, the pipeline automatically falls back to HTTP long-polling to preserve communication stability.

---

## 🛠️ Tech Stack

### Frontend (Client Side)
* **Core Logic:** JavaScript (ES6+)
* **UI/UX Framework:** React.js / Vanilla JS (with modular component architecture)
* **Styling:** CSS3 / Tailwind CSS (Optimized for RTL alignment and Persian typography)

### Backend (Server Side)
* **Runtime Environment:** Node.js
* **Application Framework:** Express.js (Lightweight routing and middleware controller)
* **Database Management:** MongoDB / Mongoose (For unstructured message archiving, chat histories, and user metadata)

### Real-Time Layer
* **Network Protocol:** Socket.IO / Raw WebSockets (Bi-directional communication engine)

---

## 📐 Real-Time Communication Architecture

The engine operates on a event-driven schema designed for speed, consistency, and low-latency message delivery:

### Key Internal Socket Events:
* `connection`: Fires upon a successful socket handshake.
* `join-room`: Allocates the user to a private or group chat thread.
* `send-message`: Transmits the dynamic message body payload asynchronously.
* `typing`: Triggers a non-blocking notification indicating active user engagement.
* `disconnect`: Automatically cleans up active connection references to free up server overhead.

---

## 📦 Local Installation & Setup

Follow these streamlined instructions to clone, configure, and execute the repository locally:

### Prerequisites
Make sure you have the following frameworks installed on your machine:
* [Node.js](https://nodejs.org) (v16.x or higher)
* [npm](https://npmjs.com) or [yarn](https://yarnpkg.com)
* [MongoDB](https://mongodb.com) (Local instance or MongoDB Atlas URI)

### 1. Clone the Repository
```bash
git clone https://github.com
cd chat-app
```

### 2. Install Project Dependencies
If the codebase uses a monorepo setup or split directories, navigate to both layers:

**For the Backend:**
```bash
cd backend
npm install
```

**For the Frontend:**
```bash
cd ../frontend
npm install
```

### 3. Environment Configurations
Create a `.env` file within your root server or backend directory and configure the environment variables:
```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/persian-chat-db
JWT_SECRET=your_super_secure_jwt_token_secret
```

### 4. Running the Development Server

**Start Backend Server:**
```bash
cd backend
npm run dev # or node server.js
```

**Start Frontend Client:**
```bash
cd ../frontend
npm start # or npm run dev
```

Open `http://localhost:3000` in your web browser to interact with your instance.

---

## 🌟 Core Features & Developer Highlights
* 🌐 **Full RTL Support:** Native alignment adjustments optimized specifically for Persian language UI rendering.
* ⚡ **Instant Messaging:** Dynamic updates without triggering standard webpage refreshes.
* 🔒 **Secure Sessions:** Ready for JSON Web Tokens (JWT) implementation to protect private communication corridors.
* 💾 **Persistent Chat Logs:** Robust database integration preventing history data loss on server restarts.