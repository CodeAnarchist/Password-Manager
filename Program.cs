using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

class Program
{
    private const string DatabaseFileName = "passwords.json"; //db name
    private const string MasterPasswordFileName = "masterpassword.bin"; //master pw
    private static Dictionary<string, PasswordEntry> passwordDatabase = new Dictionary<string, PasswordEntry>(); //pw dictionary
    private static byte[] masterPasswordHash = null; //hashed master pw

    static void Main(string[] args)
    {
        bool resetDatabase = false;

        //reset param check
        //to reset the DB and create a new master password use --reset as parameter
        if (args.Length > 0 && args[0] == "--reset")
        {
            resetDatabase = true;
        }
        if (args.Length > 0 && args[0] == "?"| args[0] == "help")
        {
            Console.WriteLine("Use --reset to reset the database");
            Console.WriteLine("Created by @CodeAnarchist");
        }

        while (true)
        {

            if (resetDatabase || !File.Exists(MasterPasswordFileName))//if there's no db or there is --reset it creates a new db and master pw file
            {
                Console.Write("Enter a new master password: ");
                string masterPassword = Console.ReadLine();
                masterPasswordHash = HashPassword(masterPassword);
                File.WriteAllBytes(MasterPasswordFileName, masterPasswordHash);
                Console.WriteLine("Master password saved.");
                break;
            }
            else
            {
                Console.Write("Enter the master password: ");
                string masterPassword = Console.ReadLine();
                masterPasswordHash = File.ReadAllBytes(MasterPasswordFileName);

                //verify master password
                if (VerifyMasterPassword(masterPassword))
                {
                    break;
                }
                else
                {
                    Console.WriteLine("Invalid master password. Please try again.");
                }
            }
        }

        //load password db
        LoadDatabase(resetDatabase);

        while (true)
        {
            Console.WriteLine("Welcome to the password manager!");
            Console.WriteLine("1. Add a password");
            Console.WriteLine("2. Delete a password for a website");
            Console.WriteLine("3. View the password archive");
            Console.WriteLine("4. Generate a Random Password");
            Console.WriteLine("5. Exit");
            Console.Write("Choose an option: ");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    AddPassword();
                    break;
                case "2":
                    DeletePassword();
                    break;
                case "3":
                    ShowPasswordArchive();
                    break;
                case "5":
                    SaveDatabase();
                    Environment.Exit(0);
                    break;
                case "4":
                    PWGen();
                    break;
                default:
                    Console.WriteLine("Invalid option. Please try again.");
                    break;
            }
        }
    }
    private static void PWGen() {
    
            Console.Write("Enter the desired password length: ");
            if (int.TryParse(Console.ReadLine(), out int passwordLength) && passwordLength > 0)
            {
                string generatedPassword = GenerateRandomPassword(passwordLength);
                Console.WriteLine($"Generated password: {generatedPassword}");
            }
            else
            {
                Console.WriteLine("Invalid password length. Please enter a positive integer.");
            }

        }

    private static bool VerifyMasterPassword(string inputPassword)
    {
        byte[] inputPasswordHash = HashPassword(inputPassword);
        return StructuralComparisons.StructuralEqualityComparer.Equals(inputPasswordHash, masterPasswordHash);
    }

    private static byte[] HashPassword(string password)
    {
        //hash password with sha254 
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }

    private static void LoadDatabase(bool reset)
    {
        if (reset || !File.Exists(DatabaseFileName))
        {
            //reset the db or create a new one
            passwordDatabase = new Dictionary<string, PasswordEntry>();
            SaveDatabase();
            Console.WriteLine("Database reset or created.");
        }
        else
        {
            try
            {
                //read and deserialize the pw
                string databaseJson = File.ReadAllText(DatabaseFileName);
                passwordDatabase = JsonConvert.DeserializeObject<Dictionary<string, PasswordEntry>>(databaseJson);
                DecryptPasswords();
                Console.WriteLine("Database loaded successfully.");
            }
            catch (JsonException)
            {
                Console.WriteLine("Error loading the database. The format may be corrupted.");
            }
        }
    }

    private static void SaveDatabase()
    {
        //encrypt pw and save it on db
        EncryptPasswords();
        string databaseJson = JsonConvert.SerializeObject(passwordDatabase, Formatting.Indented);
        File.WriteAllText(DatabaseFileName, databaseJson);
        Console.WriteLine("Database saved.");
    }

    private static void AddPassword()
    {
        Console.Write("Enter the username: ");
        string username = Console.ReadLine();
        Console.Write("Enter the password: ");
        string password = Console.ReadLine();
        Console.Write("Confirm the password: ");
        string confirmPassword = Console.ReadLine();
        Console.Write("Enter the website URL: ");
        string website = Console.ReadLine();

        if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password) && password == confirmPassword)
        {
            Console.Write("Do you want to save this password? (Y/N): ");
            string confirmation = Console.ReadLine();

            if (confirmation.Trim().ToUpper() == "Y")
            {
                //use url as key in db
                string key = website;

                //encrypt pw before saving
                string encryptedPassword = EncryptString(password, website);
                passwordDatabase[key] = new PasswordEntry
                {
                    Username = username,
                    Password = encryptedPassword,
                    Website = website
                };
                Console.WriteLine("Password saved successfully.");
            }
        }
        else
        {
            Console.WriteLine("Username or password is empty or passwords do not match. Operation canceled.");
        }
    }

    private static void DeletePassword()
    {
        Console.Write("Enter the website URL to delete the password: ");
        string website = Console.ReadLine();

        string key = website;

        if (passwordDatabase.ContainsKey(key))
        {
            Console.Write("Are you sure you want to delete this password? (Y/N): ");
            string confirmation = Console.ReadLine();
            if (confirmation.Trim().ToUpper() == "Y")
            {
                //remove db voice with given site(key)
                passwordDatabase.Remove(key);
                Console.WriteLine("Password deleted successfully.");
            }
        }
        else
        {
            Console.WriteLine("Website not found in the database.");
        }
    }

    private static void ShowPasswordArchive()
    {
        Console.WriteLine("Password archive:");
        foreach (var entry in passwordDatabase)
        {
            //decrypt and print the pw
            string decryptedPassword =DecryptString(entry.Value.Password, entry.Value.Website);

            Console.WriteLine($"Website: {entry.Value.Website}, Username: {entry.Value.Username}, Password: {decryptedPassword}");
        }
    }

    private static string EncryptString(string plainText, string sitePassword)
    {
        using (Aes aesAlg = Aes.Create())
        {
            //derive a key from the master pw and the site pw using PBKDF2.
            byte[] derivedKey = DeriveKey(masterPasswordHash, Encoding.UTF8.GetBytes(sitePassword));

            aesAlg.Key = derivedKey;
            aesAlg.Mode = CipherMode.CFB;
            aesAlg.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }
                return Convert.ToBase64String(aesAlg.IV) + Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
    }

    private static void EncryptPasswords()
    {
        foreach (var entry in passwordDatabase)
        {
            string decryptedPassword = DecryptString(entry.Value.Password, entry.Value.Website);
        }
    }

    private static string DecryptString(string cipherText, string sitePassword)
    {
        using (Aes aesAlg = Aes.Create())
        {
            byte[] iv = Convert.FromBase64String(cipherText.Substring(0, 24));
            byte[] cipherBytes = Convert.FromBase64String(cipherText.Substring(24));

            //derive the decryption key
            byte[] derivedKey = DeriveKey(masterPasswordHash, Encoding.UTF8.GetBytes(sitePassword));

            aesAlg.Key = derivedKey;
            aesAlg.Mode = CipherMode.CFB;
            aesAlg.Padding = PaddingMode.PKCS7;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, iv);

            using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
    private static byte[] DeriveKey(byte[] masterKey, byte[] sitePasswordBytes)
    {
        // Use PBKDF2 to derive a key of the appropriate length.
        using (Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(masterKey, sitePasswordBytes, 10000))
        {
            return deriveBytes.GetBytes(32); //32bytes key lenght
        }
    }

    private static void DecryptPasswords()
    {
        foreach (var entry in passwordDatabase)
        {
            string decryptedPassword = DecryptString(entry.Value.Password, entry.Value.Website);
        }
    }

    private static byte[] CombineKeys(byte[] key1, byte[] key2)
    {
        //combine 2 keys in one
        byte[] combinedKey = new byte[key1.Length + key2.Length];
        Buffer.BlockCopy(key1, 0, combinedKey, 0, key1.Length);
        Buffer.BlockCopy(key2, 0, combinedKey, key1.Length, key2.Length);
        return combinedKey;
    }
    private static string GenerateRandomPassword(int length)
    {
        const string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?";

        Random rng = new Random();
        char[] password = new char[length];

        for (int i = 0; i < length; i++)
        {
            password[i] = allowedChars[rng.Next(0, allowedChars.Length)];
        }

        return new string(password);
    }

    class PasswordEntry
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Website { get; set; }
    }
}
