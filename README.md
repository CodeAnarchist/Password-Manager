Password Manager - Documentation
Made by @CodeAnarchist

Introduction:
This program is a password manager that allows the user to store and manage passwords securely(AES256). It provides features for creating, adding, deleting, and viewing passwords/username/site.

Features:
1. Secure storage of passwords using encryption.
2. Master password protection to access the password manager.
3. Option to generate random passwords.
4. Password database management (add, delete, view).
5. Data encryption using a combination of the master password and website.
6. Ability to reset the entire database.

Usage:
1. Run the program.
2. Enter your master password to access the password manager.
3. Choose from the following options:
   a. Add a password entry.
   b. Delete a password entry for a specific website.
   c. View the password archive.
   d. Generate a random password.
   e. Exit the program.

Security:
- Passwords are securely encrypted using AES encryption.
- Master password is hashed using PBKDF2.
- Passwords are decrypted only when displayed.

Please note:
- Ensure you remember your master password; it cannot be recovered if forgotten.
- Regularly back up your password database to prevent data loss.

Feedback and Contributions:
If you have suggestions or you would like to contribute to this project, please make a pull request or contact me on discord "stepleo5000".

Future update I would like to do:

1. 2FA: Add support for 2FA to enhance security.
2. Password Expiration: Implement password expiration policies for enhanced security.
3. Password Strength Checker: Provide a feature to check the strength of existing passwords.
4. Export and Import: Allow users to export and import their password database.
5. Improved User Interface: Enhance the user interface for a more intuitive experience.
6. Password Recovery: Implement a secure password recovery process for forgotten master passwords.
7. Audit Trail: Keep a log of actions performed on the password database for auditing purposes.

Thank you for using Password Manager!
