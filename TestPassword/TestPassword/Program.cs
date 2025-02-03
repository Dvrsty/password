using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

Console.Write("请输入盐值：");
string saltIsGood = Console.ReadLine()?.Trim();

Console.Write("请输入迭代次数：");
int iterations = int.Parse(Console.ReadLine()?.Trim());

Console.Write("请输入 KeyFlag：");
int keyFlag = int.Parse(Console.ReadLine()?.Trim());

Console.Write("请输入 IVFlag：");
int ivFlag = int.Parse(Console.ReadLine()?.Trim());

Console.WriteLine("Enter 1 to encrypt, enter 2 to decrypt");
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

string EncryptString(string plainText, string password)
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

string DecryptString(string cipherText, string password)
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