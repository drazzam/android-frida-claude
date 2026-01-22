// Cryptographic Operations Monitor
// Intercepts encryption, decryption, hashing, and key generation

Java.perform(function() {
    console.log("[*] Crypto Monitor Loaded");
    
    // Helper function to convert bytes to hex
    function bytesToHex(bytes) {
        if (bytes == null) return "null";
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(("0" + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join("");
    }
    
    // Helper to truncate long strings
    function truncate(str, maxLen) {
        if (str == null) return "null";
        maxLen = maxLen || 100;
        if (str.length > maxLen) {
            return str.substring(0, maxLen) + "...(" + str.length + " total)";
        }
        return str;
    }
    
    // ============================================
    // javax.crypto.Cipher
    // ============================================
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            console.log("[Cipher] getInstance: " + transformation);
            return this.getInstance(transformation);
        };
        
        Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
            var mode = opmode == 1 ? "ENCRYPT" : opmode == 2 ? "DECRYPT" : "MODE_" + opmode;
            console.log("[Cipher] init: " + mode);
            console.log("[Cipher] Key Algorithm: " + key.getAlgorithm());
            console.log("[Cipher] Key (hex): " + truncate(bytesToHex(key.getEncoded()), 64));
            return this.init(opmode, key);
        };
        
        Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, params) {
            var mode = opmode == 1 ? "ENCRYPT" : opmode == 2 ? "DECRYPT" : "MODE_" + opmode;
            console.log("[Cipher] init: " + mode + " with params");
            console.log("[Cipher] Key Algorithm: " + key.getAlgorithm());
            console.log("[Cipher] Key (hex): " + truncate(bytesToHex(key.getEncoded()), 64));
            
            // Try to get IV if IvParameterSpec
            try {
                var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
                if (Java.cast(params, IvParameterSpec)) {
                    var iv = Java.cast(params, IvParameterSpec).getIV();
                    console.log("[Cipher] IV (hex): " + bytesToHex(iv));
                }
            } catch(e) {}
            
            return this.init(opmode, key, params);
        };
        
        Cipher.doFinal.overload('[B').implementation = function(input) {
            console.log("[Cipher] doFinal");
            console.log("[Cipher] Input (hex): " + truncate(bytesToHex(input), 128));
            var result = this.doFinal(input);
            console.log("[Cipher] Output (hex): " + truncate(bytesToHex(result), 128));
            return result;
        };
        
        Cipher.doFinal.overload('[B', 'int', 'int').implementation = function(input, offset, len) {
            console.log("[Cipher] doFinal (offset)");
            console.log("[Cipher] Input (hex): " + truncate(bytesToHex(input), 128));
            var result = this.doFinal(input, offset, len);
            console.log("[Cipher] Output (hex): " + truncate(bytesToHex(result), 128));
            return result;
        };
        
        console.log("[+] Cipher monitoring installed");
    } catch(e) {
        console.log("[-] Cipher monitoring failed: " + e);
    }
    
    // ============================================
    // java.security.MessageDigest (Hashing)
    // ============================================
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("[Hash] getInstance: " + algorithm);
            return this.getInstance(algorithm);
        };
        
        MessageDigest.update.overload('[B').implementation = function(input) {
            console.log("[Hash] update: " + truncate(bytesToHex(input), 64));
            return this.update(input);
        };
        
        MessageDigest.digest.overload().implementation = function() {
            var result = this.digest();
            console.log("[Hash] digest: " + bytesToHex(result));
            return result;
        };
        
        MessageDigest.digest.overload('[B').implementation = function(input) {
            console.log("[Hash] digest input: " + truncate(bytesToHex(input), 64));
            var result = this.digest(input);
            console.log("[Hash] digest output: " + bytesToHex(result));
            return result;
        };
        
        console.log("[+] MessageDigest monitoring installed");
    } catch(e) {
        console.log("[-] MessageDigest monitoring failed: " + e);
    }
    
    // ============================================
    // javax.crypto.Mac (HMAC)
    // ============================================
    try {
        var Mac = Java.use('javax.crypto.Mac');
        
        Mac.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("[MAC] getInstance: " + algorithm);
            return this.getInstance(algorithm);
        };
        
        Mac.init.overload('java.security.Key').implementation = function(key) {
            console.log("[MAC] init with key: " + key.getAlgorithm());
            console.log("[MAC] Key (hex): " + truncate(bytesToHex(key.getEncoded()), 64));
            return this.init(key);
        };
        
        Mac.doFinal.overload('[B').implementation = function(input) {
            console.log("[MAC] doFinal input: " + truncate(bytesToHex(input), 64));
            var result = this.doFinal(input);
            console.log("[MAC] doFinal output: " + bytesToHex(result));
            return result;
        };
        
        console.log("[+] Mac monitoring installed");
    } catch(e) {
        console.log("[-] Mac monitoring failed: " + e);
    }
    
    // ============================================
    // java.security.KeyGenerator
    // ============================================
    try {
        var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
        
        KeyGenerator.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log("[KeyGen] getInstance: " + algorithm);
            return this.getInstance(algorithm);
        };
        
        KeyGenerator.generateKey.implementation = function() {
            var key = this.generateKey();
            console.log("[KeyGen] Generated key: " + key.getAlgorithm());
            console.log("[KeyGen] Key (hex): " + truncate(bytesToHex(key.getEncoded()), 64));
            return key;
        };
        
        console.log("[+] KeyGenerator monitoring installed");
    } catch(e) {
        console.log("[-] KeyGenerator monitoring failed: " + e);
    }
    
    // ============================================
    // java.security.SecureRandom
    // ============================================
    try {
        var SecureRandom = Java.use('java.security.SecureRandom');
        
        SecureRandom.nextBytes.implementation = function(bytes) {
            this.nextBytes(bytes);
            console.log("[SecureRandom] Generated " + bytes.length + " bytes: " + truncate(bytesToHex(bytes), 32));
        };
        
        console.log("[+] SecureRandom monitoring installed");
    } catch(e) {
        console.log("[-] SecureRandom monitoring failed: " + e);
    }
    
    // ============================================
    // Android KeyStore
    // ============================================
    try {
        var KeyStore = Java.use('java.security.KeyStore');
        
        KeyStore.getInstance.overload('java.lang.String').implementation = function(type) {
            console.log("[KeyStore] getInstance: " + type);
            return this.getInstance(type);
        };
        
        KeyStore.getKey.implementation = function(alias, password) {
            console.log("[KeyStore] getKey: " + alias);
            return this.getKey(alias, password);
        };
        
        KeyStore.setKeyEntry.overload('java.lang.String', 'java.security.Key', '[C', '[Ljava.security.cert.Certificate;').implementation = function(alias, key, password, chain) {
            console.log("[KeyStore] setKeyEntry: " + alias);
            console.log("[KeyStore] Key algorithm: " + key.getAlgorithm());
            return this.setKeyEntry(alias, key, password, chain);
        };
        
        console.log("[+] KeyStore monitoring installed");
    } catch(e) {
        console.log("[-] KeyStore monitoring failed: " + e);
    }
    
    // ============================================
    // Base64 Encoding/Decoding
    // ============================================
    try {
        var Base64 = Java.use('android.util.Base64');
        
        Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
            console.log("[Base64] encode: " + truncate(bytesToHex(input), 32) + " -> " + truncate(this.encodeToString(input, flags), 32));
            return this.encodeToString(input, flags);
        };
        
        Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
            var result = this.decode(str, flags);
            console.log("[Base64] decode: " + truncate(str, 32) + " -> " + truncate(bytesToHex(result), 32));
            return result;
        };
        
        console.log("[+] Base64 monitoring installed");
    } catch(e) {
        console.log("[-] Base64 monitoring failed: " + e);
    }
    
    console.log("[*] Crypto Monitor Active!");
    console.log("[*] All cryptographic operations will be logged...");
});
