# SQL Hunter 0.0.1 - Websites Vulnerability Scanner

SQL Hunter is a powerful scanning tool designed to identify websites vulnerable to SQL injection attacks. By utilizing predefined search queries, known as "dorks," SQL Hunter searches the web for potential targets and then evaluates them for vulnerabilities.

## Features

- **Dork Scanner**: Search for vulnerable websites using a list of dorks provided by the user.
- **Vuln Scanner**: Identify SQL injection vulnerabilities in collected URLs.
- **Dork&Vuln Scanner**: Combines the functionalities of both the Dork Scanner and Vuln Scanner.

## How to Use

### Downloading the Compiled Tool

1. Clone the repository:
   ```bash
   git clone https://github.com/paulomunizdev/SQLHunter.git
   ```
2. Navigate to the SQLHunter directory:
   ```bash
   cd SQLHunter
   ```
3. Give permission to execute:
   ```bash
   sudo chmod +x sqlhunter
   ```
4. Run SQLHunter:
   ```bash
   sudo ./sqlhunter
   ```

### Compiling the Source Code

Before compiling, ensure that the required dependencies are installed:
```bash
sudo apt-get update
sudo apt-get install libcurl4-openssl-dev
```

Compile the source code using g++:
```bash
g++ -o sqlhunter src/sqlhunter.cpp -lcurl
```

### Running SQL Hunter

Once compiled, SQL Hunter can be executed directly from the terminal:
```bash
./sqlhunter
```

## Files

1. **sqlhunter**: Compiled tool for scanning vulnerable websites.
2. **dorks.txt**: File containing a list of dorks to be used in the Dork Scanner.
3. **src/sqlhunter.cpp**: Source code for SQL Hunter.

## Contributing

Contributions are welcome! Feel free to submit issues, feature requests, or pull requests to improve SQL Hunter.

## License

This project is licensed under the MIT License.
