/**
 * setup-certs.js
 * Generates a self-signed certificate using Node's built-in crypto.
 * No OpenSSL binary required on Windows.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const certsDir = path.join(__dirname, 'certs');
if (!fs.existsSync(certsDir)) fs.mkdirSync(certsDir);

// Try using openssl if available, otherwise use node-forge
function tryOpenSSL() {
  try {
    execSync('openssl version', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

if (tryOpenSSL()) {
  console.log('✅ OpenSSL found — generating certificates...');
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"`,
    { stdio: 'inherit' }
  );
  console.log('✅ Certificates generated in ./certs/');
} else {
  console.log('⚠️  OpenSSL not found. Installing node-forge to generate certs...');
  execSync('npm install node-forge --no-save', { stdio: 'inherit' });

  const forge = require('node-forge');
  const pki = forge.pki;

  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  const attrs = [
    { name: 'commonName', value: 'localhost' },
    { name: 'organizationName', value: 'OAuth2 Mock' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }] },
    { name: 'basicConstraints', cA: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  fs.writeFileSync('certs/server.key', pki.privateKeyToPem(keys.privateKey));
  fs.writeFileSync('certs/server.crt', pki.certificateToPem(cert));
  console.log('✅ Certificates generated in ./certs/');
}

console.log('\n🔑 To trust the cert on Windows (run as Admin in PowerShell):');
console.log('   Import-Certificate -FilePath ".\\certs\\server.crt" -CertStoreLocation Cert:\\LocalMachine\\Root');
