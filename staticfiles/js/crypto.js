/**
 * Secure File Transfer - Client-side Cryptography
 * 
 * This file contains functions for client-side encryption and decryption
 * using the Web Crypto API.
 */

// Generate an RSA key pair
async function generateRsaKeyPair() {
    try {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['encrypt', 'decrypt']
      );
      
      // Export the keys to PEM format
      const publicKeyDer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      const privateKeyDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      
      // Convert to Base64
      const publicKeyBase64 = arrayToBase64(new Uint8Array(publicKeyDer));
      const privateKeyBase64 = arrayToBase64(new Uint8Array(privateKeyDer));
      
      // Format as PEM
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
      const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
      
      return {
        publicKey: publicKeyPem,
        privateKey: privateKeyPem
      };
    } catch (error) {
      console.error('Error generating RSA key pair:', error);
      throw error;
    }
  }
  
  // Convert a PEM-encoded key to a CryptoKey object
  async function importRsaKey(pemKey, isPrivate = false) {
    try {
      // Remove header, footer, and newlines
      const pemContents = pemKey.replace(/-{5}(BEGIN|END) (PRIVATE|PUBLIC) KEY-{5}/g, '')
        .replace(/\n/g, '');
      
      // Base64 decode the PEM contents
      const binaryDer = base64ToArray(pemContents);
      
      // Import the key
      const algorithm = {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-256' }
      };
      
      const usages = isPrivate ? ['decrypt'] : ['encrypt'];
      const format = isPrivate ? 'pkcs8' : 'spki';
      
      return await crypto.subtle.importKey(
        format,
        binaryDer,
        algorithm,
        true,
        usages
      );
    } catch (error) {
      console.error('Error importing RSA key:', error);
      throw error;
    }
  }
  
  // Encrypt a private key with a password
  async function encryptPrivateKey(privateKeyPem, password) {
    try {
      // Derive a key from the password
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );
      
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      
      // Encrypt the private key
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedKey = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        new TextEncoder().encode(privateKeyPem)
      );
      
      return {
        salt: arrayToBase64(salt),
        iv: arrayToBase64(iv),
        encryptedKey: arrayToBase64(new Uint8Array(encryptedKey))
      };
    } catch (error) {
      console.error('Error encrypting private key:', error);
      throw error;
    }
  }
  
  // Decrypt a private key with a password
  async function decryptPrivateKey(encryptedData, salt, iv, password) {
    try {
      // Derive the key from the password
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );
      
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: base64ToArray(salt),
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      
      // Decrypt the private key
      const decryptedKey = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: base64ToArray(iv)
        },
        key,
        base64ToArray(encryptedData)
      );
      
      return new TextDecoder().decode(decryptedKey);
    } catch (error) {
      console.error('Error decrypting private key:', error);
      throw error;
    }
  }
  
  // Encrypt a file with AES-GCM
  async function encryptFile(fileData) {
    try {
      // Generate a random AES key
      const aesKey = await crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: 256
        },
        true,
        ['encrypt', 'decrypt']
      );
      
      // Generate a random IV
      const iv = crypto.getRandomValues(new Uint8Array(12));
      
      // Encrypt the file
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        aesKey,
        fileData
      );
      
      // Export the AES key
      const exportedKey = await crypto.subtle.exportKey('raw', aesKey);
      
      return {
        encryptedData: new Uint8Array(encryptedData),
        aesKey: new Uint8Array(exportedKey),
        iv: iv
      };
    } catch (error) {
      console.error('Error encrypting file:', error);
      throw error;
    }
  }
  
  // Decrypt a file with AES-GCM
  async function decryptFile(encryptedData, aesKey, iv) {
    try {
      // Import the AES key
      const importedKey = await crypto.subtle.importKey(
        'raw',
        aesKey,
        {
          name: 'AES-GCM',
          length: 256
        },
        false,
        ['decrypt']
      );
      
      // Decrypt the file
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        importedKey,
        encryptedData
      );
      
      return new Uint8Array(decryptedData);
    } catch (error) {
      console.error('Error decrypting file:', error);
      throw error;
    }
  }
  
  // Encrypt an AES key with an RSA public key
  async function encryptAesKey(aesKey, publicKeyPem) {
    try {
      // Import the public key
      const publicKey = await importRsaKey(publicKeyPem);
      
      // Encrypt the AES key
      const encryptedKey = await crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP'
        },
        publicKey,
        aesKey
      );
      
      return new Uint8Array(encryptedKey);
    } catch (error) {
      console.error('Error encrypting AES key:', error);
      throw error;
    }
  }
  
  // Decrypt an AES key with an RSA private key
  async function decryptAesKey(encryptedKey, privateKeyPem) {
    try {
      // Import the private key
      const privateKey = await importRsaKey(privateKeyPem, true);
      
      // Decrypt the AES key
      const decryptedKey = await crypto.subtle.decrypt(
        {
          name: 'RSA-OAEP'
        },
        privateKey,
        encryptedKey
      );
      
      return new Uint8Array(decryptedKey);
    } catch (error) {
      console.error('Error decrypting AES key:', error);
      throw error;
    }
  }
  
  // Calculate SHA-256 hash of a file
  async function calculateFileHash(fileData) {
    try {
      const hashBuffer = await crypto.subtle.digest('SHA-256', fileData);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (error) {
      console.error('Error calculating file hash:', error);
      throw error;
    }
  }
  
  // Verify SHA-256 hash of a file
  async function verifyFileHash(fileData, expectedHash) {
    try {
      const actualHash = await calculateFileHash(fileData);
      return actualHash === expectedHash;
    } catch (error) {
      console.error('Error verifying file hash:', error);
      throw error;
    }
  }
  
  // Convert a Uint8Array to a Base64 string
  function arrayToBase64(array) {
    return btoa(String.fromCharCode.apply(null, array));
  }
  
  // Convert a Base64 string to a Uint8Array
  function base64ToArray(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  }
  
  // Store keys in local storage
  function storeKeys(publicKey, privateKey) {
    localStorage.setItem('publicKey', publicKey);
    localStorage.setItem('privateKey', privateKey);
  }
  
  // Retrieve keys from local storage
  function getKeys() {
    return {
      publicKey: localStorage.getItem('publicKey'),
      privateKey: localStorage.getItem('privateKey')
    };
  }