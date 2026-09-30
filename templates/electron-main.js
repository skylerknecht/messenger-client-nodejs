const { app, BrowserWindow, ipcMain, session } = require('electron');
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

app.on('window-all-closed', () => { app.quit(); });

{% if exit_on_close %}
ipcMain.on('exit-on-close', () => { process.exit(0); });
{% endif %}

app.on('ready', async () => {
    mainWindow = await createWindow();
});
