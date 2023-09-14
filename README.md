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


Security:
- Passwords are securely encrypted using AES encryption.
- Master password is hashed using PBKDF2.
- Passwords are decrypted only when displayed.

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
