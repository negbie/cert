# cert

cert attempts to load a CA from the name-cert.pem and name-key.pem files. If this does not succeed, it generates a new CA and saves it to disk.

### Example

```bash
ca := NewCertificateAuthority("name")
&tls.Config{GetCertificate: ca.GetCertificate}

```