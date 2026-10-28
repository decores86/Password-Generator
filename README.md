# Secure Password Generator for Windows

A small Windows desktop app that generates random passwords locally. It lets you choose how many passwords to create, their length, and minimum counts for lowercase letters, uppercase letters, digits, and symbols.

## Features

- Generate 1?100 passwords, each 4?128 characters long.
- Set minimum counts for lowercase letters, uppercase letters, digits, and symbols.
- Use Windows' cryptographic random number generator for password characters and shuffling.
- Copy a generated password to the clipboard.
- View an approximate strength estimate.
- Optionally check a password against Have I Been Pwned's Pwned Passwords service using its k-anonymity range API.

## Requirements

- Windows with Windows PowerShell and Windows Forms available (the built-in Windows PowerShell is suitable).
- Internet access only for the optional breach check.

## Run

1. Download `PassGenerator.ps1` from this repository.
2. Open PowerShell in the folder containing the file.
3. Run:

   ```powershell  .\PassGenerator.ps1
   ```

You can also right-click the `.ps1` file and choose **Run with PowerShell**. The script does not need administrator rights.

## Use

1. Choose how many passwords to generate and the password length.
2. Set the minimum number of lowercase letters, uppercase letters, digits, and symbols. A category is included in the remaining characters when its minimum is greater than zero. If all minimums are zero, all four categories are used.
3. Make sure the sum of the minimums does not exceed the selected length.
4. Select **Generate passwords**.
5. Use **COPY** to copy a password. Treat the clipboard as sensitive: Windows clipboard history or clipboard manager software may retain copied text.
6. **Strength** shows an approximate estimate. **Leak check** is optional and requires an internet connection.

## Privacy and security

- Passwords are generated on the local computer and displayed in the app. The script does not save them to files or send them to a server as part of generation.
- The optional leak check computes a SHA-1 hash locally and sends only its first five hexadecimal characters to `api.pwnedpasswords.com` over HTTPS. The service returns matching hash suffixes; the script compares the full suffix locally. The password itself is not sent.
- Do not paste real passwords into public issues, discussions, screenshots, or source files. Do not commit generated passwords or secrets to a repository.
- Close the app when finished and clear the clipboard if you copied a password and do not want it retained there.

## Limitations

- The strength label is a rough estimate based on password length and character categories. It is not a guarantee that a password is safe for every account or policy.
- The leak check only reports whether the password appears in the service's known corpus; no match does not prove that a password has never been exposed.
- The script currently has no automated test suite and has not been independently security-audited.

## License

No license is specified yet. Add a license before inviting others to reuse, modify, or redistribute the script.
