using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Shouldly;

static string Process(bool encrypt, string keyString, string input)
{
    // We undo replacing of the 2 characters from Base64 which where not URL safe 
    if (!encrypt)
    {
        input = input.Replace("-", "+").Replace("_", "/");
    }

    // Get UTF8 byte array of input string for encryption
    var inputBytes = Encoding.UTF8.GetBytes(input);

    // Again, get UTF8 byte array of key for use in encryption
    var keyBytes = Encoding.UTF8.GetBytes(keyString);

    // Padding the key to 256
    var myHash = new Sha256Digest();
    myHash.BlockUpdate(keyBytes, 0, keyBytes.Length);
    var keyBytesPadded = new byte[myHash.GetDigestSize()];
    myHash.DoFinal(keyBytesPadded, 0);

    // Initialize AES CTR (counter) mode cipher from the BouncyCastle cryptography library
    var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");

    cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", keyBytesPadded), new byte[16]));

    // As this is a stream cipher, you can process bytes chunk by chunk until complete, then close with DoFinal.
    // In our case we don't need a stream, so we simply call DoFinal() to encrypt the entire input at once.
    var encryptedBytes = cipher.DoFinal(inputBytes);

    // The encryption is complete, however we still need to get the encrypted byte array into a useful form for passing as a URL parameter
    // First, we convert the encrypted byte array to a Base64 string to make it use ASCII characters
    var base64EncryptedOutputString = Convert.ToBase64String(encryptedBytes);

    // Lastly, we replace the 2 characters from Base64 which are not URL safe ( + and / ) with ( - and _ ) as recommended in IETF RFC4648
    var urlEncodedBase64EncryptedOutputString = base64EncryptedOutputString;

    if (encrypt)
    {
        urlEncodedBase64EncryptedOutputString =
            urlEncodedBase64EncryptedOutputString.Replace("+", "-").Replace("/", "_");
    }

    // This final string is now safe to be passed around, into our web service by URL, etc.
    return urlEncodedBase64EncryptedOutputString;
}

static string Encrypt(string keyString, string input)
{
    return Process(true, keyString, input);
}

static string Decrypt(string keyString, string input)
{
    return Process(false, keyString, input);
}

const string key = "supersecret";
const string message = "hello world!";

Decrypt(key, Encrypt(key, message)).ShouldBe(message);