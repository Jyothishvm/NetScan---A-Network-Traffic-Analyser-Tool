const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let mainWindow;
let backendProcess;

const isDev = !app.isPackaged;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false, // For simplicity in this demo wrapper
            webSecurity: false // Disable web security for local file fetching if needed
        },
        title: "NetScan Advanced Thread Detection",
        autoHideMenuBar: true,
        show: false // Don't show until ready
    });

    if (isDev) {
        // In dev mode, wait for Vite to start up
        mainWindow.loadURL('http://localhost:5173');
        mainWindow.webContents.openDevTools();
    } else {
        // In production, load the built HTML bundle
        mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
    }

    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

function startBackend() {
    if (isDev) {
        // In development mode, we assume you are running the backend separately
        // If we wanted to run it, we would spawn python but let's just rely on standard terminal for dev
        console.log("Running in dev mode. Ensure the Python FastAPI backend is running on port 8000");
        createWindow();
    } else {
        // In production, spawn the bundled executable
        const executablePath = path.join(process.resourcesPath, 'netscan-engine.exe');
        console.log('Spawning backend from:', executablePath);

        // Spawn the backend
        try {
            backendProcess = spawn(executablePath, [], {
                detached: false, // Tie lifecycle to the electron app
                stdio: 'ignore'  // Don't capture logs to avoid crashing buffer
            });

            backendProcess.on('error', (err) => {
                console.error('Failed to start backend engine:', err);
            });

            backendProcess.on('exit', (code) => {
                console.log(`Backend engine exited with code ${code}`);
            });

            // Wait for port 8000 to be open before creating window
            waitForServer(8000, 10000, () => {
                console.log("Backend server is ready!");
                createWindow();
            });
        } catch (e) {
            console.error("Critical error spawning backend", e);
            // show window anyway to unblock user or show error UI if we had one
            createWindow();
        }
    }
}

function waitForServer(port, timeoutMs, callback) {
    const start = Date.now();

    function attempt() {
        if (Date.now() - start > timeoutMs) {
            console.warn("Timed out waiting for backend server. Launching UI anyway.");
            callback();
            return;
        }

        // Simple HTTP GET request to check if server is up
        const req = http.request(`http://127.0.0.1:${port}/api/status/wakeup`, { method: 'GET' }, (res) => {
            // Any response means server is up
            callback();
        });

        req.on('error', () => {
            // Server not up yet, try again in 500ms
            setTimeout(attempt, 500);
        });

        req.end();
    }

    attempt();
}

app.whenReady().then(startBackend);

app.on('window-all-closed', () => {
    if (backendProcess) {
        console.log("Killing backend process...");
        try {
            backendProcess.kill('SIGINT');
        } catch (e) {
            console.error(e);
        }
    }
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (mainWindow === null) {
        startBackend();
    }
});
