/* dosya: ca_server.js */
const net = require('net');
const crypto = require('crypto');

// ... (Key generation kısımları aynı kalıyor) ...
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const server = net.createServer((socket) => {
    const remoteAddress = socket.remoteAddress + ':' + socket.remotePort;
    
    // Hata yönetimi (Çökmemesi için)
    socket.on('error', (err) => {
        if (err.code !== 'ECONNRESET') console.error(`Socket hatası: ${err.message}`);
    });

    socket.on('data', (data) => {
        try {
            const msgString = data.toString();
            if (!msgString.trim()) return;

            const request = JSON.parse(msgString);
            console.log(`Sertifika İsteği: ${request.subject_id}`);

            // Sertifika oluşturma
            const unsignedCert = {
                serial_number: Date.now(),
                issuer: "IZU_BIM437_CA",
                validity: "2024-2025",
                subject_id: request.subject_id,
                subject_public_key: request.public_key
            };

            const sign = crypto.createSign('SHA256');
            sign.update(JSON.stringify(unsignedCert));
            const signature = sign.sign(privateKey, 'base64');

            const signedCertificate = {
                ...unsignedCert,
                ca_signature: signature,
                ca_public_key: publicKey 
            };

            socket.end(JSON.stringify(signedCertificate));
            
            console.log(`-> Sertifika yollandı ve bağlantı sonlandırıldı: ${request.subject_id}`);

        } catch (e) {
            console.error("İşlem Hatası:", e.message);
        }
    });
});

server.listen(8000, '0.0.0.0', () => {
    console.log("CA Sunucusu Hazır (0.0.0.0:8000)");
});