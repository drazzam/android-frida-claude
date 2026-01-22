# 🤖 Android + Frida Remote Executor for Claude

**Zero Cost | No Root Required | Autonomous Android Security Testing**

This repository enables **Claude AI to autonomously control an Android emulator with Frida** for security research, app analysis, and automated testing.

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    CLAUDE AUTONOMOUS ANDROID CONTROL                        │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌─────────────────┐        ngrok tunnel        ┌──────────────────────┐  │
│  │    CLAUDE AI    │◄──────────────────────────►│   GITHUB ACTIONS     │  │
│  │   (claude.ai)   │    HTTPS REST API          │   (KVM-enabled)      │  │
│  │                 │                            │                      │  │
│  │  Uses:          │    Endpoints:              │  • Android Emulator  │  │
│  │  android_remote │    • /execute (Python)     │  • Frida Tools       │  │
│  │  _executor.py   │    • /bash (shell)         │  • ADB Access        │  │
│  │                 │    • /adb (Android)        │  • APK Patching      │  │
│  │                 │    • /frida/* (hooking)    │  • Remote Executor   │  │
│  │                 │    • /apk/* (management)   │                      │  │
│  └─────────────────┘                            └──────────────────────┘  │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                    FRIDA GADGET (NO ROOT!)                           │ │
│  │                                                                      │ │
│  │  objection patchapk -s app.apk  →  app.objection.apk                │ │
│  │                                                                      │ │
│  │  • Injects libfrida-gadget.so into APK                              │ │
│  │  • Adds System.loadLibrary("frida-gadget") to smali                 │ │
│  │  • No root required - embedded in APK                               │ │
│  │  • Process name becomes "Gadget" when running                       │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

## ✨ Features

| Feature | Description |
|---------|-------------|
| **KVM Acceleration** | 15-second emulator boot time (FREE on GitHub Actions since April 2024) |
| **No Root Required** | Frida Gadget injection via `objection` - works on any APK |
| **Autonomous Control** | Claude can execute Python, bash, ADB, and Frida commands |
| **SSL Bypass** | Built-in SSL pinning bypass scripts |
| **Network Monitor** | Track all HTTP/HTTPS requests from the app |
| **APK Management** | Download, patch, install, and launch apps |
| **Real-time Hooking** | Load custom Frida scripts on the fly |

## 🚀 Quick Start

### Step 1: Fork & Setup Repository

1. **Fork this repository** (or create a new one with these files)

2. **Add ngrok Secret**:
   - Get free token at [ngrok.com/signup](https://ngrok.com)
   - Go to: Repository → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `NGROK_AUTH_TOKEN`
   - Value: Your ngrok auth token

### Step 2: Start the Workflow

1. Go to **Actions** tab
2. Select **"Android Emulator + Frida + Claude Remote Executor"**
3. Click **"Run workflow"**
4. Configure:
   - Session duration (15-60 minutes)
   - Android API level (28-33)
5. Click **"Run workflow"**

### Step 3: Connect Claude

1. **Watch the workflow logs** for the public URL:
   ```
   ════════════════════════════════════════════════════════════════════
   🎯 CLAUDE REMOTE EXECUTOR IS READY!
   ════════════════════════════════════════════════════════════════════

   📡 PUBLIC URL: https://xxxx-xx-xx-xxx-xx.ngrok-free.app
   ```

2. **Give Claude the URL** with this prompt:

   ```
   I have an Android Remote Executor running. Here's the connection:
   
   URL: https://xxxx-xx-xx-xxx-xx.ngrok-free.app
   
   Please connect using the android_remote_executor.py client and help me
   analyze this APK: [URL or describe your task]
   ```

## 📚 API Reference

### System Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | List all capabilities |
| `/health` | GET | System health + emulator status |
| `/disk` | GET | Disk usage info |

### Execution Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/execute` | POST | Execute Python code |
| `/bash` | POST | Execute bash commands |
| `/adb` | POST | Execute ADB commands |
| `/adb/devices` | GET | List ADB devices |
| `/adb/packages` | GET | List installed packages |

### Frida Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/frida/connect` | POST | Connect Frida to emulator |
| `/frida/processes` | GET | List running processes |
| `/frida/attach` | POST | Attach to a process |
| `/frida/script` | POST | Load Frida JavaScript |
| `/frida/ssl-bypass` | POST | Bypass SSL pinning |
| `/frida/network-monitor` | POST | Monitor network traffic |
| `/frida/scripts` | GET | List loaded scripts |

### APK Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/apk/patch` | POST | Patch APK with Frida Gadget |
| `/apk/install` | POST | Install APK on emulator |
| `/apk/info` | GET | Get APK information |
| `/apk/launch` | POST | Launch an app |

### File Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/upload` | POST | Upload file to server |
| `/download` | POST | Download from URL |
| `/ls` | GET | List directory |
| `/read` | GET | Read file content |

## 💻 Python Client Usage

```python
from android_remote_executor import AndroidRemoteExecutor

# Connect to the running instance
executor = AndroidRemoteExecutor("https://xxxx.ngrok-free.app")

# Check health
print(executor.health())

# Execute ADB command
result = executor.adb("shell pm list packages")
print(result["stdout"])

# Full APK setup (download → patch → install → launch)
result = executor.full_setup("https://example.com/app.apk")

# Bypass SSL pinning
executor.frida_ssl_bypass()

# Load custom Frida script
executor.frida_script('''
    Java.perform(function() {
        console.log("[*] Custom hook loaded!");
        
        var Activity = Java.use("android.app.Activity");
        Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
            console.log("[+] Activity.onCreate called: " + this);
            this.onCreate(bundle);
        };
    });
''')

# Hook a specific method
executor.hook_method(
    "com.example.app.LoginActivity",
    "validatePassword",
    before_code='console.log("[*] Password: " + arguments[0]);'
)
```

## 🔧 Common Workflows

### Analyze an APK

```python
# 1. Download and get info
executor.download("https://example.com/app.apk", "/tmp/apks")
info = executor.apk_info("/tmp/apks/app.apk")
print(f"Package: {info['info']['package_name']}")

# 2. Patch with Frida Gadget
executor.apk_patch("/tmp/apks/app.apk")

# 3. Install and launch
executor.apk_install("/tmp/apks/app.objection.apk")
executor.apk_launch(info['info']['package_name'])

# 4. Connect Frida
import time
time.sleep(3)
executor.frida_connect()
executor.frida_attach("Gadget")
```

### Intercept Network Traffic

```python
# Load network monitor
executor.frida_network_monitor()

# Bypass SSL pinning
executor.frida_ssl_bypass()

# Now interact with the app - all URLs will be logged
```

### Hook Encryption Functions

```python
executor.frida_script('''
    Java.perform(function() {
        var Cipher = Java.use("javax.crypto.Cipher");
        
        Cipher.doFinal.overload("[B").implementation = function(input) {
            console.log("[Cipher.doFinal] Input: " + bytesToHex(input));
            var result = this.doFinal(input);
            console.log("[Cipher.doFinal] Output: " + bytesToHex(result));
            return result;
        };
        
        function bytesToHex(bytes) {
            var hex = [];
            for (var i = 0; i < bytes.length; i++) {
                hex.push(("0" + (bytes[i] & 0xFF).toString(16)).slice(-2));
            }
            return hex.join("");
        }
    });
''')
```

## ⚠️ Limitations

- **Session Duration**: Max 60 minutes per workflow run (GitHub Actions limit)
- **Free Tier**: 2000 minutes/month on GitHub Actions free tier
- **Architecture**: Emulator runs x86_64 (not ARM)
- **No Play Store**: Use google_apis images, not google_play_store

## 🐛 Troubleshooting

### Emulator won't boot
```bash
# Check KVM is enabled
ls -la /dev/kvm

# View emulator logs
cat /tmp/emulator.log
```

### Frida can't connect
```python
# 1. Verify port forwarding
executor.bash("adb forward tcp:27042 tcp:27042")

# 2. Check if Gadget is running
executor.adb("shell ps | grep -i gadget")

# 3. List processes
procs = executor.frida_processes()
print([p for p in procs['processes'] if 'Gadget' in p['name']])
```

### APK patching fails
```python
# Try manual patching with verbose output
result = executor.bash("objection patchapk -s /tmp/apks/app.apk -a x86_64 2>&1")
print(result["stdout"])
print(result["stderr"])
```

## 📖 References

- [GitHub Actions KVM Support](https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/)
- [Frida Documentation](https://frida.re/docs/home/)
- [Objection Wiki](https://github.com/sensepost/objection/wiki)
- [Frida Gadget](https://frida.re/docs/gadget/)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Note**: This tool is for authorized security research only. Always obtain proper authorization before testing applications you don't own.
