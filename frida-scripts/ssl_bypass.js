// SSL Pinning Bypass - Universal
// Works with most Android apps using standard SSL/TLS

Java.perform(function() {
    console.log("[*] SSL Pinning Bypass Loaded");
    
    // ============================================
    // Standard TrustManager Bypass
    // ============================================
    try {
        var TrustManager = Java.registerClass({
            name: 'com.frida.TrustManager',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', 
            '[Ljavax.net.ssl.TrustManager;', 
            'java.security.SecureRandom'
        );
        
        SSLContext_init.implementation = function(km, tm, sr) {
            console.log("[+] SSLContext.init() intercepted");
            SSLContext_init.call(this, km, TrustManagers, sr);
        };
        console.log("[+] TrustManager bypass installed");
    } catch(e) {
        console.log("[-] TrustManager bypass failed: " + e);
    }
    
    // ============================================
    // OkHttp Certificate Pinner (v3.x)
    // ============================================
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3: Bypassing pin for " + hostname);
        };
        CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3: Bypassing pin (kotlin) for " + hostname);
        };
        console.log("[+] OkHttp3 CertificatePinner bypass installed");
    } catch(e) {
        console.log("[-] OkHttp3 not found or bypass failed: " + e);
    }
    
    // ============================================
    // OkHttp Certificate Pinner (v4.x)
    // ============================================
    try {
        var CertificatePinner4 = Java.use('okhttp3.CertificatePinner');
        if (CertificatePinner4.check$okhttp) {
            CertificatePinner4.check$okhttp.implementation = function(hostname, peerCertificates) {
                console.log("[+] OkHttp4: Bypassing pin for " + hostname);
            };
            console.log("[+] OkHttp4 CertificatePinner bypass installed");
        }
    } catch(e) {
        console.log("[-] OkHttp4 not found: " + e);
    }
    
    // ============================================
    // Trustkit
    // ============================================
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
            console.log("[+] TrustKit: Bypassing verify for " + hostname);
            return true;
        };
        TrustKit.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(hostname, certificate) {
            console.log("[+] TrustKit: Bypassing verify for " + hostname);
            return true;
        };
        console.log("[+] TrustKit bypass installed");
    } catch(e) {
        console.log("[-] TrustKit not found: " + e);
    }
    
    // ============================================
    // Android Network Security Config
    // ============================================
    try {
        var NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NetworkSecurityTrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log("[+] NetworkSecurityConfig: Bypassing for authType " + authType);
        };
        console.log("[+] NetworkSecurityConfig bypass installed");
    } catch(e) {
        console.log("[-] NetworkSecurityConfig not found: " + e);
    }
    
    // ============================================
    // WebView SSL Handler
    // ============================================
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] WebView: Accepting SSL error");
            handler.proceed();
        };
        console.log("[+] WebView SSL bypass installed");
    } catch(e) {
        console.log("[-] WebView bypass failed: " + e);
    }
    
    console.log("[*] SSL Pinning Bypass Active!");
});
