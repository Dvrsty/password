using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

const string saltIsGood = "SaltIsGood";
const int keyFlag = 8;
const int ivFlag = 8;
const int iterations = 8;

Console.WriteLine("Input 1 to encrypt, input 2 to decrypt");
string inputType = Console.ReadLine();

if (inputType == "1")
{

    Console.Write("Enter a string to encrypt: ");
    string originalString = Console.ReadLine();

    Console.Write("Enter a password: ");
    string password = Console.ReadLine();

    string encryptedString = EncryptString(originalString, password);
    Console.WriteLine($"Encrypted string: {encryptedString}");
}
else if (inputType == "2")
{
    Console.Write("Enter a string to decrypt: ");
    string encryptedString = Console.ReadLine();

    Console.Write("Enter a password: ");
    string password = Console.ReadLine();

    string decryptedString = DecryptString(encryptedString, password);
    Console.WriteLine($"Decrypted string: {decryptedString}");
}
else
{
    Console.WriteLine("error");
}

// 等待用户输入后退出程序
Console.WriteLine("Press any key to exit...");
Console.ReadKey();

static string EncryptString(string plainText, string password)
{
    using (var aes = Aes.Create())
    {
        var key = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(saltIsGood), iterations);
        aes.Key = key.GetBytes(aes.KeySize / keyFlag);
        aes.IV = key.GetBytes(aes.BlockSize / ivFlag);

        using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
        using (var ms = new MemoryStream())
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(plainText);
            }
            return Convert.ToBase64String(ms.ToArray());
        }
    }
}

static string DecryptString(string cipherText, string password)
{
    using (var aes = Aes.Create())
    {
        var key = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(saltIsGood), iterations);
        aes.Key = key.GetBytes(aes.KeySize / keyFlag);
        aes.IV = key.GetBytes(aes.BlockSize / ivFlag);

        using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
        using (var ms = new MemoryStream(Convert.FromBase64String(cipherText)))
        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
        using (var sr = new StreamReader(cs))
        {
            return sr.ReadToEnd();
        }
    }
}