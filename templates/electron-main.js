const { app, BrowserWindow, session } = require('electron');
const path = require('path');

const USER_AGENT = '{{ user_agent }}';

app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
    event.preventDefault();
    callback(true);
});

let mainWindow = null;

async function createWindow() {
    session.defaultSession.setUserAgent(USER_AGENT);

    let thisWindow = new BrowserWindow({
        width: 0,
        height: 0,
        show: false,
        skipTaskbar: true,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            backgroundThrottling: false,
            v8CacheOptions: 'none'
        }
    });

    thisWindow.loadFile(path.join(__dirname, 'renderer.html'));
    return thisWindow;
}

app.on('window-all-closed', () => {});

app.on('ready', async () => {
    mainWindow = await createWindow();
});
