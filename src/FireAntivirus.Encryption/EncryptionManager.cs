using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FireAntivirus.Encryption
{
    public class EncryptionManager
    {
        // AES加密 - 使用更安全的实现
        public string EncryptAes(string plaintext, string key)
        {
            using (Aes aes = Aes.Create())
            {
                // 从密码派生密钥（Pbkdf2 静态方法；SHA1 与旧 Rfc2898DeriveBytes 默认等价，保持旧密文可解）
                byte[] derived = Rfc2898DeriveBytes.Pbkdf2(key, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 48);
                aes.Key = derived[..32];
                aes.IV = derived[32..48];

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                        cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        // AES解密
        public string DecryptAes(string ciphertext, string key)
        {
            using (Aes aes = Aes.Create())
            {
                byte[] derived = Rfc2898DeriveBytes.Pbkdf2(key, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 48);
                aes.Key = derived[..32];
                aes.IV = derived[32..48];

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(ciphertext)))
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }

        // 文件加密
        public void EncryptFile(string inputFile, string outputFile, string key)
        {
            using (Aes aes = Aes.Create())
            {
                byte[] derived = Rfc2898DeriveBytes.Pbkdf2(key, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 48);
                aes.Key = derived[..32];
                aes.IV = derived[32..48];

                using (FileStream inputStream = new FileStream(inputFile, FileMode.Open))
                using (FileStream outputStream = new FileStream(outputFile, FileMode.Create))
                {
                    // 写入IV到文件开头
                    outputStream.Write(aes.IV, 0, aes.IV.Length);

                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] buffer = new byte[1024 * 1024]; // 1MB buffer
                        int bytesRead;
                        while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            cryptoStream.Write(buffer, 0, bytesRead);
                        }
                    }
                }
            }
        }

        // 文件解密
        public void DecryptFile(string inputFile, string outputFile, string key)
        {
            using (Aes aes = Aes.Create())
            {
                using (FileStream inputStream = new FileStream(inputFile, FileMode.Open))
                {
                    // 从文件开头读取IV
                    byte[] iv = new byte[16];
                    inputStream.ReadExactly(iv, 0, iv.Length);
                    aes.IV = iv;

                    // 从密码派生密钥
                    aes.Key = Rfc2898DeriveBytes.Pbkdf2(key, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 32);

                    using (FileStream outputStream = new FileStream(outputFile, FileMode.Create))
                    using (CryptoStream cryptoStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        byte[] buffer = new byte[1024 * 1024]; // 1MB buffer
                        int bytesRead;
                        while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                }
            }
        }

        // SHA256哈希计算
        public string ComputeSha256(string input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = sha256.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        // 文件SHA256哈希计算
        public string ComputeFileSha256(string filePath)
        {
            using (SHA256 sha256 = SHA256.Create())
            using (FileStream stream = new FileStream(filePath, FileMode.Open))
            {
                byte[] hashBytes = sha256.ComputeHash(stream);
                return Convert.ToBase64String(hashBytes);
            }
        }

        // 生成随机密钥
        public string GenerateRandomKey(int length = 32)
        {
            byte[] randomBytes = RandomNumberGenerator.GetBytes(length);
            return Convert.ToBase64String(randomBytes).Substring(0, length);
        }

        // 生成密码哈希
        public string HashPassword(string password)
        {
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 32);
            return Convert.ToBase64String(hash);
        }

        // 验证密码
        public bool VerifyPassword(string password, string hashedPassword)
        {
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 32);
            return Convert.ToBase64String(hash).Equals(hashedPassword);
        }

        // 加密文件流
        public void EncryptStream(Stream inputStream, Stream outputStream, string key)
        {
            using (Aes aes = Aes.Create())
            {
                byte[] derived = Rfc2898DeriveBytes.Pbkdf2(key, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 48);
                aes.Key = derived[..32];
                aes.IV = derived[32..48];

                // 写入IV到输出流开头
                outputStream.Write(aes.IV, 0, aes.IV.Length);

                using (CryptoStream cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[1024 * 1024]; // 1MB buffer
                    int bytesRead;
                    while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cryptoStream.Write(buffer, 0, bytesRead);
                    }
                }
            }
        }

        // 解密文件流
        public void DecryptStream(Stream inputStream, Stream outputStream, string key)
        {
            using (Aes aes = Aes.Create())
            {
                // 从输入流开头读取IV
                byte[] iv = new byte[16];
                inputStream.ReadExactly(iv, 0, iv.Length);
                aes.IV = iv;

                // 从密码派生密钥
                aes.Key = Rfc2898DeriveBytes.Pbkdf2(key, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 32);

                using (CryptoStream cryptoStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    byte[] buffer = new byte[1024 * 1024]; // 1MB buffer
                    int bytesRead;
                    while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        outputStream.Write(buffer, 0, bytesRead);
                    }
                }
            }
        }

        // 生成RSA密钥对
        public (string publicKey, string privateKey) GenerateRsaKeyPair(int keySize = 2048)
        {
            using (RSA rsa = RSA.Create(keySize))
            {
                string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                return (publicKey, privateKey);
            }
        }

        // RSA加密
        public string EncryptRsa(string plaintext, string publicKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                byte[] encryptedBytes = rsa.Encrypt(plaintextBytes, RSAEncryptionPadding.OaepSHA256);
                return Convert.ToBase64String(encryptedBytes);
            }
        }

        // RSA解密
        public string DecryptRsa(string ciphertext, string privateKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
                byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
                byte[] decryptedBytes = rsa.Decrypt(ciphertextBytes, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }

        // 生成HMAC
        public string ComputeHmac(string input, string key)
        {
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = hmac.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        // 验证HMAC
        public bool VerifyHmac(string input, string key, string expectedHmac)
        {
            string computedHmac = ComputeHmac(input, key);
            return computedHmac.Equals(expectedHmac);
        }

        // 生成随机初始化向量
        public byte[] GenerateRandomIV(int length = 16)
        {
            return RandomNumberGenerator.GetBytes(length);
        }
    }
}
