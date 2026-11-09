using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FireAntivirus.Encryption
{
    public class EncryptionManager
    {
        // AES加密 - 随机盐 + PBKDF2-SHA256 + 随机 IV（密文前缀 FAVE2$ 标识新格式）
        public string EncryptAes(string plaintext, string key)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] iv;
            byte[] keyBytes;
            using (var derive = new Rfc2898DeriveBytes(key, salt, 100000, HashAlgorithmName.SHA256))
            {
                keyBytes = derive.GetBytes(32);
                iv = derive.GetBytes(16);
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                        cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    // FAVE2$ + base64(salt[16] + iv[16] + ciphertext)
                    string payload = Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(iv) + ":" + Convert.ToBase64String(ms.ToArray());
                    return "FAVE2$" + Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
                }
            }
        }

        // AES解密 - 按 FAVE2$ 前缀分流：新格式随机盐/IV 解密；旧格式（静态盐+固定IV）兼容解密
        public string DecryptAes(string ciphertext, string key)
        {
            byte[][] parts;
            if (ciphertext.StartsWith("FAVE2$", StringComparison.Ordinal))
            {
                string payload = Encoding.UTF8.GetString(Convert.FromBase64String(ciphertext.Substring(6)));
                var seg = payload.Split(':');
                parts = new[] { Convert.FromBase64String(seg[0]), Convert.FromBase64String(seg[1]), Convert.FromBase64String(seg[2]) };
            }
            else
            {
                // 旧格式: 静态盐 "FireAntivirusSalt" + 固定 IV（存量密文兼容, 新写入一律 FAVE2$）
                byte[] derived = Rfc2898DeriveBytes.Pbkdf2(key, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 48);
                parts = new[] { derived[..32], derived[32..48], Convert.FromBase64String(ciphertext) };
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = parts[0];
                aes.IV = parts[1];

                using (MemoryStream ms = new MemoryStream(parts[2]))
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

        // 文件加密 - 新格式文件头: "FAVE2" magic + salt[16] + iv[16] + 密文
        public void EncryptFile(string inputFile, string outputFile, string key)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] iv;
            byte[] keyBytes;
            using (var derive = new Rfc2898DeriveBytes(key, salt, 100000, HashAlgorithmName.SHA256))
            {
                keyBytes = derive.GetBytes(32);
                iv = derive.GetBytes(16);
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = iv;

                using (FileStream inputStream = new FileStream(inputFile, FileMode.Open))
                using (FileStream outputStream = new FileStream(outputFile, FileMode.Create))
                {
                    // 写入新格式文件头
                    byte[] header = new byte[5 + 16 + 16];
                    Encoding.ASCII.GetBytes("FAVE2").CopyTo(header, 0);
                    salt.CopyTo(header, 5);
                    iv.CopyTo(header, 21);
                    outputStream.Write(header, 0, header.Length);

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

        // 文件解密 - 按 "FAVE2" magic 分流：新格式读 salt+iv；旧格式文件头裸 IV 兼容
        public void DecryptFile(string inputFile, string outputFile, string key)
        {
            using (Aes aes = Aes.Create())
            {
                using (FileStream inputStream = new FileStream(inputFile, FileMode.Open))
                {
                    byte[] magic = new byte[5];
                    inputStream.ReadExactly(magic, 0, 5);

                    if (Encoding.ASCII.GetString(magic) == "FAVE2")
                    {
                        // 新格式: salt[16] + iv[16]
                        byte[] salt = new byte[16];
                        inputStream.ReadExactly(salt, 0, 16);
                        byte[] iv = new byte[16];
                        inputStream.ReadExactly(iv, 0, 16);
                        aes.IV = iv;
                        using (var derive = new Rfc2898DeriveBytes(key, salt, 100000, HashAlgorithmName.SHA256))
                        {
                            aes.Key = derive.GetBytes(32);
                        }
                    }
                    else
                    {
                        // 旧格式: 文件头裸 IV + 静态盐派生密钥（存量文件兼容）
                        byte[] iv = new byte[16];
                        Array.Copy(magic, iv, 5);
                        inputStream.ReadExactly(iv, 5, 11);
                        aes.IV = iv;
                        aes.Key = Rfc2898DeriveBytes.Pbkdf2(key, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 32);
                    }

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

        // 生成密码哈希: PBKDF2-SHA256 + 随机盐（格式: FAV2$iter$saltB64$hashB64）
        public string HashPassword(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            const int iterations = 100000;
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
            return $"FAV2${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        }

        // 验证密码: 新格式按存储参数校验（恒时比较）; 旧格式（静态盐 SHA1）兼容校验
        public bool VerifyPassword(string password, string hashedPassword)
        {
            if (string.IsNullOrEmpty(hashedPassword)) return false;

            if (hashedPassword.StartsWith("FAV2$", StringComparison.Ordinal))
            {
                try
                {
                    var parts = hashedPassword.Split('$');
                    int iterations = int.Parse(parts[1]);
                    byte[] salt = Convert.FromBase64String(parts[2]);
                    byte[] expected = Convert.FromBase64String(parts[3]);
                    byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
                    return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(actual, expected);
                }
                catch
                {
                    return false;
                }
            }

            // 旧格式兼容: PBKDF2-SHA1 + 静态盐
            byte[] legacy = Rfc2898DeriveBytes.Pbkdf2(password, Encoding.UTF8.GetBytes("FireAntivirusSalt"), 100000, HashAlgorithmName.SHA1, 32);
            return Convert.ToBase64String(legacy).Equals(hashedPassword);
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
