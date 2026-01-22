// Network Traffic Monitor
// Logs all HTTP/HTTPS requests made by the app

Java.perform(function() {
    console.log("[*] Network Traffic Monitor Loaded");
    
    // ============================================
    // java.net.URL Monitoring
    // ============================================
    try {
        var URL = Java.use('java.net.URL');
        
        URL.$init.overload('java.lang.String').implementation = function(url) {
            console.log("[URL] NEW: " + url);
            return this.$init(url);
        };
        
        URL.openConnection.overload().implementation = function() {
            console.log("[URL] OPEN: " + this.toString());
            return this.openConnection();
        };
        
        console.log("[+] java.net.URL monitoring installed");
    } catch(e) {
        console.log("[-] URL monitoring failed: " + e);
    }
    
    // ============================================
    // HttpURLConnection Monitoring
    // ============================================
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        
        HttpURLConnection.setRequestMethod.implementation = function(method) {
            console.log("[HTTP] Method: " + method + " -> " + this.getURL().toString());
            return this.setRequestMethod(method);
        };
        
        HttpURLConnection.setRequestProperty.implementation = function(key, value) {
            console.log("[HTTP] Header: " + key + ": " + value);
            return this.setRequestProperty(key, value);
        };
        
        HttpURLConnection.getInputStream.implementation = function() {
            console.log("[HTTP] GET Response: " + this.getURL().toString());
            console.log("[HTTP] Response Code: " + this.getResponseCode());
            return this.getInputStream();
        };
        
        HttpURLConnection.getOutputStream.implementation = function() {
            console.log("[HTTP] POST/PUT Body being written to: " + this.getURL().toString());
            return this.getOutputStream();
        };
        
        console.log("[+] HttpURLConnection monitoring installed");
    } catch(e) {
        console.log("[-] HttpURLConnection monitoring failed: " + e);
    }
    
    // ============================================
    // OkHttp3 Monitoring
    // ============================================
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        var RealCall = Java.use('okhttp3.internal.connection.RealCall');
        
        RealCall.execute.implementation = function() {
            var request = this.request();
            console.log("[OkHttp] " + request.method() + " " + request.url().toString());
            
            // Log headers
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log("[OkHttp] Header: " + headers.name(i) + ": " + headers.value(i));
            }
            
            // Log body if present
            var body = request.body();
            if (body != null) {
                console.log("[OkHttp] Has Body: true, Content-Type: " + body.contentType());
            }
            
            var response = this.execute();
            console.log("[OkHttp] Response: " + response.code() + " " + response.message());
            
            return response;
        };
        
        RealCall.enqueue.implementation = function(callback) {
            var request = this.request();
            console.log("[OkHttp ASYNC] " + request.method() + " " + request.url().toString());
            return this.enqueue(callback);
        };
        
        console.log("[+] OkHttp3 monitoring installed");
    } catch(e) {
        console.log("[-] OkHttp3 monitoring failed: " + e);
    }
    
    // ============================================
    // Retrofit Monitoring
    // ============================================
    try {
        var Retrofit = Java.use('retrofit2.Retrofit');
        
        Retrofit.create.implementation = function(service) {
            console.log("[Retrofit] Creating service: " + service);
            console.log("[Retrofit] Base URL: " + this.baseUrl().toString());
            return this.create(service);
        };
        
        console.log("[+] Retrofit monitoring installed");
    } catch(e) {
        console.log("[-] Retrofit not found: " + e);
    }
    
    // ============================================
    // WebView Request Monitoring
    // ============================================
    try {
        var WebView = Java.use('android.webkit.WebView');
        
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("[WebView] LOAD: " + url);
            return this.loadUrl(url);
        };
        
        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
            console.log("[WebView] LOAD: " + url);
            console.log("[WebView] Headers: " + headers);
            return this.loadUrl(url, headers);
        };
        
        WebView.postUrl.implementation = function(url, data) {
            console.log("[WebView] POST: " + url);
            console.log("[WebView] Data length: " + data.length);
            return this.postUrl(url, data);
        };
        
        console.log("[+] WebView monitoring installed");
    } catch(e) {
        console.log("[-] WebView monitoring failed: " + e);
    }
    
    // ============================================
    // Socket Monitoring (Low Level)
    // ============================================
    try {
        var Socket = Java.use('java.net.Socket');
        
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            console.log("[Socket] CONNECT: " + host + ":" + port);
            return this.$init(host, port);
        };
        
        Socket.$init.overload('java.net.InetAddress', 'int').implementation = function(addr, port) {
            console.log("[Socket] CONNECT: " + addr.getHostAddress() + ":" + port);
            return this.$init(addr, port);
        };
        
        console.log("[+] Socket monitoring installed");
    } catch(e) {
        console.log("[-] Socket monitoring failed: " + e);
    }
    
    console.log("[*] Network Traffic Monitor Active!");
    console.log("[*] Interact with the app to see network requests...");
});
