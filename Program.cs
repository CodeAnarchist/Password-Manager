using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

class Program
{
    private const string LogFileName = "passwords.log"; //log name
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
            LogToFile($"Help was been shown");
        }
        LogToFile($"Password Manager was been opened");

        while (true)
        {

            if (resetDatabase || !File.Exists(MasterPasswordFileName))//if there's no db or there is --reset it creates a new db and master pw file
            {
                Console.Write("Enter a new master password: ");
                string masterPassword = Console.ReadLine();
                masterPasswordHash = HashPassword(masterPassword);
                File.WriteAllBytes(MasterPasswordFileName, masterPasswordHash);
                Console.WriteLine("Master password saved.");
                System.IO.File.WriteAllText(LogFileName, string.Empty);
                LogToFile($"Database and log were been reset");
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
            Console.WriteLine("Welcome to the password manager!\n");
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
                    PWGen();
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
    private static void PWGen() {
    //generate a random PW
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
    private static void LogToFile(string message)//log generator
    {
        if (!File.Exists(LogFileName))
        {
            //if there isn't a log, it will create it 
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

    private static bool IsPasswordStrong(string password)
    {
        //define a strong pw
        const int minLength = 8;
        const int minUpperCase = 1;
        const int minLowerCase = 1;
        const int minDigits = 1;
        const int minSpecialChars = 1;

        //check min lenght
        if (password.Length < minLength)
        {
            return false;
        }

        //check uppercase
        if (password.Count(char.IsUpper) < minUpperCase)
        {
            return false;
        }

        //check lowercase
        if (password.Count(char.IsLower) < minLowerCase)
        {
            return false;
        }

        //check number
        if (password.Count(char.IsDigit) < minDigits)
        {
            return false;
        }

        //check spescial character
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
            if (IsPasswordStrong(password))
            {
                Console.Write("Do you want to save this password? (Y/N): ");
                string confirmation = Console.ReadLine();

                if (confirmation.Trim().ToUpper() == "Y")
                {
                    // Usa l'URL come chiave nel database
                    string key = website;

                    // Crittografa la password prima di salvarla
                    string encryptedPassword = EncryptString(password, website);
                    passwordDatabase[key] = new PasswordEntry
                    {
                        Username = username,
                        Password = encryptedPassword,
                        Website = website
                    };
                    Console.WriteLine("Password saved successfully.");
                    LogToFile($"Added password for website: {website}");
                }
            }
            else
            {
                Console.WriteLine("The password is not strong enough. It should meet certain criteria.");
                Console.Write("Are you sure you want to use this password? (Y/N): ");
                string confirmation = Console.ReadLine();

                if (confirmation.Trim().ToUpper() == "Y")
                {
                    // Usa l'URL come chiave nel database
                    string key = website;

                    // Crittografa la password nonostante sia debole
                    string encryptedPassword = EncryptString(password, website);
                    passwordDatabase[key] = new PasswordEntry
                    {
                        Username = username,
                        Password = encryptedPassword,
                        Website = website
                    };
                    Console.WriteLine("Password saved successfully.");
                    LogToFile($"Added password for website: {website}");
                }
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
                LogToFile($"{website} password was been remove");

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
        LogToFile($"Archive was been shown");
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
        LogToFile($"Random password generated");

        return new string(password);
    }
    private static void OpenLogFile()
    {
        if (!File.Exists(LogFileName))
        {
            // Se il file di log non esiste, crea un file vuoto
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
        LogToFile($"Log file was been shown");
        // Ora puoi aprire e leggere il file di log
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
    }
}
