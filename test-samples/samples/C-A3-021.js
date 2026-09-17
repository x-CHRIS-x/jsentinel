/**
 * Test Clean Sample 021 (A3)
 * Safe, compliant implementations.
 */

// Clean: cloud storage operations dispatched through authenticated backend endpoint
async function uploadToCloudStorageSecure(fileBlob) {
    const res = await fetch("/api/cloud/upload", {
        method: "POST",
        body: fileBlob
    });
    return res.json();
}

// Variation signature: #1
