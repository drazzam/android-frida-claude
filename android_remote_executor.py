"""
Android + Frida Remote Executor Client
=======================================
This module allows Claude to connect to a GitHub Actions-hosted
Android emulator with Frida for autonomous security testing.

Usage:
    from android_remote_executor import AndroidRemoteExecutor
    
    # Initialize with your ngrok URL from GitHub Actions
    executor = AndroidRemoteExecutor("https://xxxx-xx-xx-xxx-xx.ngrok-free.app")
    
    # Check connection and emulator status
    health = executor.health()
    
    # Execute ADB commands
    result = executor.adb("shell pm list packages")
    
    # Patch APK with Frida Gadget
    result = executor.apk_patch("/tmp/apks/myapp.apk")
    
    # Install patched APK
    result = executor.apk_install("/tmp/apks/myapp.objection.apk")
    
    # Connect Frida and bypass SSL
    result = executor.frida_ssl_bypass()
    
    # Load custom Frida script
    result = executor.frida_script('''
        Java.perform(function() {
            console.log("Hello from Frida!");
        });
    ''')
"""

import httpx
from typing import Optional, Dict, Any, Union
from pathlib import Path


class AndroidRemoteExecutor:
    """Client for connecting to Android + Frida Remote Executor"""
    
    def __init__(self, base_url: str, timeout: int = 300):
        """
        Initialize the remote executor client.
        
        Args:
            base_url: The ngrok public URL from GitHub Actions output
            timeout: Default timeout in seconds for requests
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)
        
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make a request to the remote executor"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.client.request(method, url, **kwargs)
            return response.json()
        except httpx.TimeoutException:
            return {"success": False, "error": "Request timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ============== System Endpoints ==============
    
    def health(self) -> Dict[str, Any]:
        """
        Check if the remote executor is online and get system stats.
        
        Returns:
            Dict with: status, cpu_percent, memory_percent, disk_free_gb,
                      emulator_connected, frida_version, frida_session_active
        """
        return self._request("GET", "/health")
    
    def info(self) -> Dict[str, Any]:
        """Get server info and list all available endpoints"""
        return self._request("GET", "/")
    
    def disk(self) -> Dict[str, Any]:
        """Get disk usage information"""
        return self._request("GET", "/disk")
    
    # ============== Code Execution ==============
    
    def execute(self, code: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute Python code on the remote instance.
        
        Args:
            code: Python code to execute
            timeout: Optional timeout override
            
        Returns:
            Dict with: success, stdout, stderr, result, error
        """
        payload = {"code": code}
        if timeout:
            payload["timeout"] = timeout
        return self._request("POST", "/execute", json=payload)
    
    def bash(self, command: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute a bash command on the remote instance.
        
        Args:
            command: Bash command to execute
            timeout: Optional timeout override
            
        Returns:
            Dict with: success, returncode, stdout, stderr
        """
        payload = {"command": command}
        if timeout:
            payload["timeout"] = timeout
        return self._request("POST", "/bash", json=payload)
    
    # ============== ADB Commands ==============
    
    def adb(self, command: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute an ADB command on the connected emulator.
        
        Args:
            command: ADB command (without 'adb' prefix)
            timeout: Optional timeout override
            
        Returns:
            Dict with: success, command, stdout, stderr
            
        Examples:
            executor.adb("devices")
            executor.adb("shell pm list packages")
            executor.adb("install /tmp/app.apk")
        """
        payload = {"command": command}
        if timeout:
            payload["timeout"] = timeout
        return self._request("POST", "/adb", json=payload)
    
    def adb_devices(self) -> Dict[str, Any]:
        """List connected ADB devices"""
        return self._request("GET", "/adb/devices")
    
    def adb_packages(self, filter: Optional[str] = None) -> Dict[str, Any]:
        """
        List installed packages on emulator.
        
        Args:
            filter: Optional package name filter (case-insensitive)
        """
        params = {}
        if filter:
            params["filter"] = filter
        return self._request("GET", "/adb/packages", params=params)
    
    # ============== Frida Operations ==============
    
    def frida_connect(self) -> Dict[str, Any]:
        """
        Connect to Frida on the emulator.
        This sets up port forwarding and connects the Frida client.
        
        Returns:
            Dict with: success, device, message
        """
        return self._request("POST", "/frida/connect")
    
    def frida_processes(self) -> Dict[str, Any]:
        """
        List processes visible to Frida.
        
        Returns:
            Dict with: success, processes (list of {pid, name})
        """
        return self._request("GET", "/frida/processes")
    
    def frida_attach(self, process_name: str = "Gadget") -> Dict[str, Any]:
        """
        Attach Frida to a process.
        
        Args:
            process_name: Process name to attach to (default: "Gadget" for patched APKs)
            
        Returns:
            Dict with: success, message, session
        """
        return self._request("POST", f"/frida/attach?process_name={process_name}")
    
    def frida_script(self, script: str, process_name: str = "Gadget", 
                     script_name: str = "default") -> Dict[str, Any]:
        """
        Load and run a Frida JavaScript script.
        
        Args:
            script: Frida JavaScript code
            process_name: Process to attach to
            script_name: Name identifier for this script
            
        Returns:
            Dict with: success, script_name, message, initial_messages
            
        Example:
            executor.frida_script('''
                Java.perform(function() {
                    console.log("[*] Script loaded!");
                    var Activity = Java.use("android.app.Activity");
                    Activity.onResume.implementation = function() {
                        console.log("[+] Activity resumed: " + this);
                        this.onResume();
                    };
                });
            ''')
        """
        payload = {
            "script": script,
            "process_name": process_name,
            "script_name": script_name
        }
        return self._request("POST", "/frida/script", json=payload)
    
    def frida_ssl_bypass(self, process_name: str = "Gadget") -> Dict[str, Any]:
        """
        Load SSL pinning bypass script.
        Bypasses TrustManager and OkHttp certificate pinning.
        
        Args:
            process_name: Process to attach to
            
        Returns:
            Dict with script loading result
        """
        return self._request("POST", f"/frida/ssl-bypass?process_name={process_name}")
    
    def frida_network_monitor(self, process_name: str = "Gadget") -> Dict[str, Any]:
        """
        Load network monitoring script.
        Logs all URL connections and OkHttp requests.
        
        Args:
            process_name: Process to attach to
            
        Returns:
            Dict with script loading result
        """
        return self._request("POST", f"/frida/network-monitor?process_name={process_name}")
    
    def frida_scripts(self) -> Dict[str, Any]:
        """List currently loaded Frida scripts"""
        return self._request("GET", "/frida/scripts")
    
    def frida_unload(self, script_name: str) -> Dict[str, Any]:
        """
        Unload a Frida script.
        
        Args:
            script_name: Name of script to unload
        """
        return self._request("DELETE", f"/frida/script/{script_name}")
    
    # ============== APK Operations ==============
    
    def apk_patch(self, apk_path: str, architecture: str = "x86_64") -> Dict[str, Any]:
        """
        Patch APK with Frida Gadget using objection.
        
        This injects libfrida-gadget.so into the APK, enabling Frida
        hooking without root access.
        
        Args:
            apk_path: Path to the APK file on the remote server
            architecture: Target architecture (x86_64 for emulator)
            
        Returns:
            Dict with: success, original_apk, patched_apk, message
        """
        payload = {
            "apk_path": apk_path,
            "architecture": architecture
        }
        return self._request("POST", "/apk/patch", json=payload)
    
    def apk_install(self, apk_path: str) -> Dict[str, Any]:
        """
        Install APK on the emulator.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Dict with: success, apk_path, stdout, stderr
        """
        return self._request("POST", f"/apk/install?apk_path={apk_path}")
    
    def apk_info(self, apk_path: str) -> Dict[str, Any]:
        """
        Get APK information (package name, version, SDK levels).
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Dict with: success, info (package_name, version_code, etc.)
        """
        return self._request("GET", f"/apk/info?apk_path={apk_path}")
    
    def apk_launch(self, package_name: str) -> Dict[str, Any]:
        """
        Launch an app on the emulator.
        
        Args:
            package_name: Package name of the app
            
        Returns:
            Dict with: success, package, stdout, stderr
        """
        return self._request("POST", f"/apk/launch?package_name={package_name}")
    
    # ============== File Operations ==============
    
    def upload(self, filepath: str, destination: str = "/tmp/apks") -> Dict[str, Any]:
        """
        Upload a local file to the remote server.
        
        Args:
            filepath: Local path to the file
            destination: Remote directory to upload to
            
        Returns:
            Dict with: success, filepath, filename, size_bytes
        """
        path = Path(filepath)
        if not path.exists():
            return {"success": False, "error": f"Local file not found: {filepath}"}
        
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            data = {"destination": destination}
            
            url = f"{self.base_url}/upload"
            try:
                response = self.client.post(url, files=files, data=data)
                return response.json()
            except Exception as e:
                return {"success": False, "error": str(e)}
    
    def download(self, url: str, destination: str = "/tmp/downloads",
                 filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Download a file from URL to the remote server.
        
        Args:
            url: URL to download from
            destination: Remote directory to save to
            filename: Optional filename override
            
        Returns:
            Dict with: success, filepath, size_mb
        """
        payload = {"url": url, "destination": destination}
        if filename:
            payload["filename"] = filename
        return self._request("POST", "/download", json=payload)
    
    def ls(self, path: str = "/tmp") -> Dict[str, Any]:
        """
        List directory contents on the remote server.
        
        Args:
            path: Directory path to list
            
        Returns:
            Dict with: success, path, items (list of files/dirs)
        """
        return self._request("GET", "/ls", params={"path": path})
    
    def read(self, path: str, max_size: int = 1048576) -> Dict[str, Any]:
        """
        Read file content from the remote server.
        
        Args:
            path: Path to the file
            max_size: Maximum file size to read (default 1MB)
            
        Returns:
            Dict with: success, path, content
        """
        return self._request("GET", "/read", params={"path": path, "max_size": max_size})
    
    # ============== Convenience Methods ==============
    
    def full_setup(self, apk_url: str) -> Dict[str, Any]:
        """
        Complete setup: download APK, patch with Frida, install, and launch.
        
        Args:
            apk_url: URL to download the APK from
            
        Returns:
            Dict with all step results
        """
        results = {"steps": []}
        
        # Step 1: Download APK
        print("📥 Downloading APK...")
        dl_result = self.download(apk_url, "/tmp/apks")
        results["steps"].append({"step": "download", "result": dl_result})
        if not dl_result.get("success"):
            results["success"] = False
            results["error"] = "Download failed"
            return results
        
        apk_path = dl_result["filepath"]
        
        # Step 2: Get APK info
        print("📋 Getting APK info...")
        info_result = self.apk_info(apk_path)
        results["steps"].append({"step": "info", "result": info_result})
        
        package_name = info_result.get("info", {}).get("package_name")
        
        # Step 3: Patch APK
        print("🔧 Patching APK with Frida Gadget...")
        patch_result = self.apk_patch(apk_path)
        results["steps"].append({"step": "patch", "result": patch_result})
        if not patch_result.get("success"):
            results["success"] = False
            results["error"] = "Patching failed"
            return results
        
        patched_apk = patch_result["patched_apk"]
        
        # Step 4: Install patched APK
        print("📲 Installing patched APK...")
        install_result = self.apk_install(patched_apk)
        results["steps"].append({"step": "install", "result": install_result})
        if not install_result.get("success"):
            results["success"] = False
            results["error"] = "Installation failed"
            return results
        
        # Step 5: Launch app
        if package_name:
            print(f"🚀 Launching {package_name}...")
            launch_result = self.apk_launch(package_name)
            results["steps"].append({"step": "launch", "result": launch_result})
        
        # Step 6: Connect Frida
        print("🔌 Connecting Frida...")
        import time
        time.sleep(3)  # Wait for app to start
        
        frida_result = self.frida_connect()
        results["steps"].append({"step": "frida_connect", "result": frida_result})
        
        results["success"] = True
        results["package_name"] = package_name
        results["message"] = "Full setup complete! Ready for Frida hooking."
        
        print("✅ Setup complete!")
        return results
    
    def hook_method(self, class_name: str, method_name: str, 
                    before_code: str = "", after_code: str = "") -> Dict[str, Any]:
        """
        Generate and load a Frida hook for a specific method.
        
        Args:
            class_name: Full Java class name (e.g., "com.example.MyClass")
            method_name: Method name to hook
            before_code: JavaScript code to run before the method
            after_code: JavaScript code to run after the method
            
        Returns:
            Dict with script loading result
        """
        script = f'''
        Java.perform(function() {{
            var targetClass = Java.use("{class_name}");
            
            targetClass.{method_name}.implementation = function() {{
                console.log("[*] Called: {class_name}.{method_name}");
                console.log("[*] Arguments: " + JSON.stringify(arguments));
                
                {before_code}
                
                var result = this.{method_name}.apply(this, arguments);
                
                console.log("[*] Return value: " + result);
                
                {after_code}
                
                return result;
            }};
            
            console.log("[+] Hooked: {class_name}.{method_name}");
        }});
        '''
        
        return self.frida_script(script, script_name=f"hook_{method_name}")


def test_connection(base_url: str) -> bool:
    """Test if the remote executor is reachable and the emulator is running"""
    executor = AndroidRemoteExecutor(base_url)
    result = executor.health()
    
    if result.get("status") == "healthy":
        print("✅ Connected to Android Remote Executor")
        print(f"   CPU: {result.get('cpu_percent')}%")
        print(f"   Memory: {result.get('memory_percent')}%")
        print(f"   Disk Free: {result.get('disk_free_gb')} GB")
        print(f"   Emulator: {'✅ Connected' if result.get('emulator_connected') else '❌ Not connected'}")
        print(f"   Frida: v{result.get('frida_version')}")
        print(f"   Session: {'Active' if result.get('frida_session_active') else 'Inactive'}")
        return True
    else:
        print(f"❌ Connection failed: {result.get('error', 'Unknown error')}")
        return False


# Example usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        test_connection(url)
    else:
        print("Usage: python android_remote_executor.py <ngrok_url>")
        print("\nExample workflow:")
        print("  1. Start GitHub Actions workflow")
        print("  2. Copy the ngrok URL from the output")
        print("  3. Run: python android_remote_executor.py https://xxxx.ngrok-free.app")
