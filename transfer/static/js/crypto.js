/**
 * Client-side crypto utilities
 */

// Store keys in localStorage
function storeKeys(publicKey, privateKey) {
    localStorage.setItem('publicKey', publicKey);
    localStorage.setItem('privateKey', privateKey);
}

// Retrieve keys from localStorage
function getKeys() {
    return {
        publicKey: localStorage.getItem('publicKey'),
        privateKey: localStorage.getItem('privateKey'),
    };
}

// Create a file request with server-generated keys
async function createFileRequest(data) {
    try {
        const response = await fetch('/api/file-requests/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        
        return await response.json();
    } catch (error) {
        console.error("Error creating file request:", error);
        throw error;
    }
}

// Function to encrypt a file before upload (to be implemented)
async function encryptFile(fileData, publicKey) {
    // This would be a client-side encryption implementation
    // For now, return a placeholder
    return {
        encryptedData: fileData,
        encryptionDetails: {
            algorithm: "AES-256-GCM",
            publicKey: publicKey
        }
    };
}
