Password Manager
Made by @CodeAnarchist

Introduction:
This program is a password manager that allows the user to store and manage passwords securely using AES256 encryption. It provides features for creating, adding, deleting, and viewing passwords, usernames, and associated websites.

Features:
1. Secure storage of passwords using AES encryption.
2. Master password protection to access the password manager.
3. Option to generate random passwords.
4. Password database management (add, delete, view).
5. Data encryption using a combination of the master password and website.
6. Ability to reset the entire database.
7. Password strength checking to ensure the security of your passwords.
8. Logging of operations performed in the password manager.

Usage:
1. Run the program.
2. Enter your master password to access the password manager.
3. Choose from the following options:
   a. Add a password entry.
   b. Delete a password entry for a specific website.
   c. View the password archive.
   d. Generate a random password.
   e. Open and view the program's log file.
   f. Exit the program.

Parameters:
- `--reset`: Use this parameter to reset the entire password database and create a new master password. Example: `PasswordManager.exe --reset`
- `--help` or `?`: Use this parameter to display help information about the program's usage. Example: `PasswordManager.exe --help`
Note: If no parameters are provided, the program will run in its regular mode, prompting you to enter the master password or create a new one if it doesn't exist.


Security: security is paramount when it comes to managing passwords, as they represent a critical part of an individual's digital identity. The Password Manager has been designed with robust security measures to ensure the safety of stored passwords and sensitive information.
- AES Encryption (Advanced Encryption Standard): Passwords are stored using AES encryption, specifically AES-256, which is considered one of the most secure encryption algorithms available. This encryption ensures that even if the database file falls into the wrong hands, the passwords remain protected and unreadable without the correct decryption key.
- Master Password Protection: Access to the Password Manager is guarded by a master password. The master password serves as a cryptographic key to unlock and access the stored passwords. It is essential to choose a strong and unique master password that is difficult for others to guess.
- PBKDF2 Hashing (Password-Based Key Derivation Function 2): The master password is securely hashed using PBKDF2. This key derivation function adds an additional layer of security by making it computationally expensive for attackers to crack the master password, even if they have access to the hashed version.
- Salted Passwords: To further enhance security, each password is salted before encryption. A unique random value known as a "salt" is generated for each password. The salt is then combined with the user's password before encryption. This ensures that even if two users have the same password, their encrypted passwords will be different due to the unique salt.
- Decryption Only When Needed: Passwords are decrypted only when they need to be displayed, such as when viewing the password archive. This means that the actual passwords are kept encrypted and are only briefly decrypted for the user to see. This minimizes the exposure of sensitive data.


Please note:
- Ensure you remember your master password; it cannot be recovered if forgotten.
- Regularly back up your password database to prevent data loss.

Feedback and Contributions:
If you have suggestions or you would like to contribute to this project, please make a pull request or contact me on discord "stepleo5000".

Future Updates:
1. Two-Factor Authentication (2FA): Add support for 2FA to enhance security.
2. Password Expiration: Implement password expiration policies for enhanced security.
3. Export and Import: Allow users to export and import their password database.
4. Improved User Interface: Enhance the user interface for a more intuitive experience.
5. Password Recovery: Implement a secure password recovery process for forgotten master passwords.

Thank you for using Password Manager!