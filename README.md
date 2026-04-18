# Rakshak

Rakshak is a ransomware detection and prevention tool that monitors your system in real-time to identify and block ransomware attacks before they can encrypt your files.

<img width="1918" height="1018" alt="Screenshot 2026-04-18 160543" src="https://github.com/user-attachments/assets/ceed5e83-ae87-4d54-aff0-2ed9cd662159" />


## Features

- **Real-time File Monitoring** - Watch for suspicious file modifications across your system
- **Entropy Analysis** - Detect high-entropy encryption operations
- **Velocity Detection** - Identify rapid file changes indicating mass encryption
- **VSS (Volume Shadow Copy) Monitoring** - Prevent ransomware from deleting system backups
- **Network Isolation** - Automatically isolate infected systems from the network
- **C2 Correlation** - Detect command and control communications
- **Process Kill Switch** - Terminate malicious processes on detection
- **Defense Evasion Detection** - Monitor for attempts to disable security tools

## Installation

### Prerequisites

- **Rust** (latest stable) - [Install via rustup](https://rustup.rs/)
- **Node.js** (v18+) - [Download from nodejs.org](https://nodejs.org/)
- **npm** or **yarn**
- **Visual Studio Build Tools** (Windows) - Required for Rust compilation

### Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Rakshak
   ```

2. **Install frontend dependencies**
   ```bash
   cd frontend
   npm install
   ```

3. **Build the application**
   ```bash
   npm run tauri build
   ```

   Or for development mode:
   ```bash
   npm run tauri dev
   ```

## Running the Application

After building, the executable will be located at:
- `frontend/src-tauri/target/release/rakshak.exe` (Windows)

Or run in development mode:
```bash
cd frontend
npm run tauri dev
```

## Tech Stack

- **Backend**: Rust with Tauri 2.0
- **Frontend**: React 19 + TypeScript + Vite
- **UI**: Tailwind CSS 4 + Framer Motion + Recharts

## Project Structure

```
Rakshak/
├── frontend/           # React frontend application
│   ├── src/           # React components and pages
│   └── src-tauri/     # Tauri/Rust backend
│       └── src/       # Rust source code
└── README.md
```

## License

MIT
