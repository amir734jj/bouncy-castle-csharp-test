using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Shouldly;

// See: https://stackoverflow.com/a/75841861/1834787

static byte[] Process(bool encrypt, string keyMaterial, byte[] input)
{
    // Keyderivation via SHA256
    var keyMaterialBytes = Encoding.UTF8.GetBytes(keyMaterial);
    var digest = new Sha256Digest();
    digest.BlockUpdate(keyMaterialBytes, 0, keyMaterialBytes.Length);
    var keyBytes = new byte[digest.GetDigestSize()];
    digest.DoFinal(keyBytes, 0);

    // Encryption/Decryption with AES-CTR using a static IV
    var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
    cipher.Init(encrypt, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", keyBytes), new byte[16]));
    return cipher.DoFinal(input);
}

static string Encrypt(string keyMaterial, string plaintext)
{
    var plaintextBytes = Encoding.UTF8.GetBytes(plaintext); // UTF-8 encode
    var ciphertextBytes = Process(true, keyMaterial, plaintextBytes);
    return Convert.ToBase64String(ciphertextBytes).Replace("+", "-").Replace("/", "_"); // Base64url encode
}

static string Decrypt(string keyMaterial, string ciphertext)
{
    var ciphertextBytes = Convert.FromBase64String(ciphertext.Replace("-", "+").Replace("_", "/")); // Base64url decode
    var decryptedBytes = Process(false, keyMaterial, ciphertextBytes);
    return Encoding.UTF8.GetString(decryptedBytes); // UTF-8 decode
}

const string key = "supersecret";
const string message = "hello world!";

Decrypt(key, Encrypt(key, message)).ShouldBe(message);