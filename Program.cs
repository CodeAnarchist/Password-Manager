using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using System.Threading;
using System.Collections;
using System.Text.RegularExpressions;

class Program
{
    private const string LogFileName = "passwords.log"; //log file
    private const string DatabaseFileName = "passwords.json"; //db name
    private const string MasterPasswordFileName = "masterpassword.bin"; //master pw file
    private static Dictionary<string, PasswordEntry> passwordDatabase = new Dictionary<string, PasswordEntry>(); //pw dictionary
    private static byte[] masterPasswordHash = null; //hashed master pw

    static void Main(string[] args)
    {
        bool resetDatabase = false;

        //check param
        if (args.Length > 0 && args[0] == "--reset")
        {
            resetDatabase = true;
        }

        if (args.Length > 0 && (args[0] == "?" || args[0] == "help"))
        {
            Console.WriteLine("Use --reset to reset the database");
            Console.WriteLine("Created by @CodeAnarchist");
            LogToFile($"Help has been displayed");
        }
        LogToFile($"Password Manager has been opened");

        while (true)
        {
            if (resetDatabase || !File.Exists(MasterPasswordFileName)) //if there's no db or --reset, create a new db and master password file
            {
                Console.Write("Enter a new master password: ");
                string masterPassword = Console.ReadLine();
                masterPasswordHash = HashPassword(masterPassword);
                File.WriteAllBytes(MasterPasswordFileName, masterPasswordHash);
                Console.WriteLine("Master password saved.");
                System.IO.File.WriteAllText(LogFileName, string.Empty);
                LogToFile($"Database and log have been reset");
                break;
            }
            else
            {
                Console.Write("Enter the master password: ");
                string masterPassword = Console.ReadLine();
                masterPasswordHash = File.ReadAllBytes(MasterPasswordFileName);

                //verify master pw
                if (VerifyMasterPassword(masterPassword))
                {
                    break;
                }
                else
                {
                    Console.WriteLine("Invalid master password. Please try again.");
                    Thread.Sleep(3000);
                }
            }
        }

        //load db
        LoadDatabase(resetDatabase);

        while (true)
        {
            Console.WriteLine("\n\nWelcome to the password manager!\n");
            Console.WriteLine("1. Add a password");
            Console.WriteLine("2. Delete a password for a website");
            Console.WriteLine("3. View the password archive");
            Console.WriteLine("4. Generate a Random Password");
            Console.WriteLine("5. View log");
            Console.WriteLine("6. Exit\n");
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
                case "6":
                    SaveDatabase();
                    Environment.Exit(0);
                    break;
                case "4":
                    GenerateRandomPassword();
                    break;
                case "5":
                    OpenLogFile();
                    break;
                default:
                    Console.WriteLine("Invalid option. Please try again.");
                    break;
            }
        }
    }

    private static void GenerateRandomPassword()
    {
        //random pw generator
        Console.Write("Enter the desired password length: ");
        if (int.TryParse(Console.ReadLine(), out int passwordLength) && passwordLength > 0)
        {
            string generatedPassword = GenerateRandomPassword(passwordLength);
            Console.WriteLine($"Generated password: {generatedPassword}");
            LogToFile($"Generated a random password");
        }
        else
        {
            Console.WriteLine("Invalid password length. Please enter a positive integer.");
        }
    }

    private static bool VerifyMasterPassword(string inputPassword)
    {
        byte[] inputPasswordHash = HashPassword(inputPassword);

        //verify that master pw is equal to master pw hash
        if (StructuralComparisons.StructuralEqualityComparer.Equals(inputPasswordHash, masterPasswordHash))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    private static byte[] HashPassword(string password)
    {
        //hash pw with sha512
        using (var sha512 = SHA512.Create())
        {
            return sha512.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }

    private static void LoadDatabase(bool reset)
    {
        if (reset || !File.Exists(DatabaseFileName))
        {
            //create new db
            passwordDatabase = new Dictionary<string, PasswordEntry>();
            SaveDatabase();
            Console.WriteLine("Database reset or created.");
        }
        else
        {
            try
            {
                //read and deserialize pw
                string databaseJson = File.ReadAllText(DatabaseFileName);
                passwordDatabase = JsonConvert.DeserializeObject<Dictionary<string, PasswordEntry>>(databaseJson);
                //DecryptPasswords();
                Console.WriteLine("Database loaded successfully.");
            }
            catch (JsonException)
            {
                Console.WriteLine("Error loading the database. The format may be corrupted.");
            }
        }
    }

    private static void LogToFile(string message)
    {
        if (!File.Exists(LogFileName))
        {
            //if log doesn't exist, a new one'll be creatyed
            try
            {
                File.Create(LogFileName).Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating log file: {ex.Message}");
                return;
            }
        }
        try
        {
            using (StreamWriter writer = File.AppendText(LogFileName))
            {
                writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss}: {message}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing to log file: {ex.Message}");
        }
    }

    private static void SaveDatabase()
    {
        //encrypt pw
        EncryptPasswords();
        string databaseJson = JsonConvert.SerializeObject(passwordDatabase, Formatting.Indented);
        File.WriteAllText(DatabaseFileName, databaseJson);
        Console.WriteLine("Database saved.");
    }

    private static bool IsPasswordStrong(string password)
    {
        //definition of security critiria
        const int minLength = 8;
        const int minUpperCase = 1;
        const int minLowerCase = 1;
        const int minDigits = 1;
        const int minSpecialChars = 1;

        //minimum length
        if (password.Length < minLength)
        {
            return false;
        }

        //uppercase
        if (password.Count(char.IsUpper) < minUpperCase)
        {
            return false;
        }

        //lowercase
        if (password.Count(char.IsLower) < minLowerCase)
        {
            return false;
        }

        //digits
        if (password.Count(char.IsDigit) < minDigits)
        {
            return false;
        }

        //special characte
        if (password.Count(c => !char.IsLetterOrDigit(c)) < minSpecialChars)
        {
            return false;
        }

        return true;
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
            //generate a random salt
            byte[] salt = GenerateSalt();

            if (IsPasswordStrong(password))
            {
                Console.Write("Do you want to save this password? (Y/N): ");
                string confirmation = Console.ReadLine();

                if (confirmation.Trim().ToUpper() == "Y")
                {
                    //use the url as the key in the database
                    string key = website;

                    //concatenate the salt to the pw and then encrypt it
                    string saltedPassword = password + Convert.ToBase64String(salt);
                    string encryptedPassword = EncryptString(saltedPassword, website);
                    passwordDatabase[key] = new PasswordEntry
                    {
                        Username = username,
                        Password = encryptedPassword,
                        Website = website,
                        Salt = Convert.ToBase64String(salt) //save the salt in db
                    };
                    Console.WriteLine("Password saved successfully.");
                    LogToFile($"Added password for website: {website}");
                    SaveDatabase();
                }
            }
            else
            {
                Console.WriteLine("The password is not strong enough. It should meet certain criteria.");
                Console.Write("Are you sure you want to use this password? (Y/N): ");
                string confirmation = Console.ReadLine();

                if (confirmation.Trim().ToUpper() == "Y")
                {
                    //use the url as key in db
                    string key = website;

                    //concat the salt to the password even if it's weak
                    string saltedPassword = password + Convert.ToBase64String(salt);
                    string encryptedPassword = EncryptString(saltedPassword, website);
                    passwordDatabase[key] = new PasswordEntry
                    {
                        Username = username,
                        Password = encryptedPassword,
                        Website = website,
                        Salt = Convert.ToBase64String(salt)//save salt in db
                    };
                    Console.WriteLine("Password saved successfully.");
                    LogToFile($"Added password for website: {website}");
                    SaveDatabase();
                }
            }
        }
        else
        {
            Console.WriteLine("Username or password is empty or passwords do not match. Operation canceled.");
        }
    }

    private static byte[] GenerateSalt()
    {
        byte[] salt = new byte[512]; //4096-bit salt
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(salt);
        }
        return salt;
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
                //remove the db entry
                passwordDatabase.Remove(key);
                Console.WriteLine("Password deleted successfully.");
                LogToFile($"{website} password has been removed");
                SaveDatabase();
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
            //decrypt the pw and then print it
            string decryptedPassword = DecryptString(entry.Value.Password, entry.Value.Website, entry.Value.Salt).ToString().Replace(entry.Value.Salt.ToString(), "");

            Console.WriteLine($"Website: {entry.Value.Website}, Username: {entry.Value.Username}, Password: {decryptedPassword}");
        }
        LogToFile($"Archive has been displayed");
    }

    private static string EncryptString(string plainText, string sitePassword)
    {
        using (Aes aesAlg = Aes.Create())
        {
            //derive a key from the master pw and the site password using PBKDF2
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
            string decryptedPassword = DecryptString(entry.Value.Password, entry.Value.Website, entry.Value.Salt);
        }
    }

    private static string DecryptString(string cipherText, string sitePassword, string salt)
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
            //Console.WriteLine(aesAlg.Mode+"  "+ aesAlg.Padding);
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, iv);

            using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        // Console.WriteLine(sitePassword+"  "+salt);
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }

    private static byte[] DeriveKey(byte[] masterKey, byte[] sitePasswordBytes)
    {
        //use PBKDF2 to derive a key of the appropriate length.
        using (Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(masterKey, sitePasswordBytes, 10000))
        {
            return deriveBytes.GetBytes(32);
        }
    }

    private static byte[] CombineKeys(byte[] key1, byte[] key2)
    {
        //deprecated
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
        LogToFile($"Generated a random password");

        return new string(password);
    }

    private static void OpenLogFile()
    {
        if (!File.Exists(LogFileName))
        {
            //if the log file does not exist, create an empty file
            try
            {
                File.Create(LogFileName).Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating log file: {ex.Message}");
                return;
            }
        }
        LogToFile($"Log file has been displayed");
        try
        {
            string logContents = File.ReadAllText(LogFileName);
            Console.WriteLine("Log file contents:");
            Console.WriteLine(logContents);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading log file: {ex.Message}");
        }
    }

    class PasswordEntry
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Website { get; set; }
        public string Salt { get; set; }
    }
}
