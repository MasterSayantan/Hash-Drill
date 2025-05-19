# Hash-Drill

Hash-Drill is a smart terminal-based hash cracking tool written in Python. It automates the process of cracking cryptographic hashes (MD5, SHA1, SHA256, SHA512) using a wordlist dictionary attack.

## Features

- Accepts single hash input or hash lists from a file.
- Supports multiple hashing algorithms: md5, sha1, sha256, sha512.
- Takes a custom wordlist file as input for brute force attempts.
- Displays a live progress bar showing tried passwords and speed.
- Logs successful crack attempts to a structured `output.log` file with timestamps.
- Gracefully handles invalid inputs, missing files, and unsupported hash types.
- Compatible with Linux, macOS, and Windows.
- Works fully offline — no external API dependency.
- Includes `--verbose` and `--silent` mode switches.
- Bonus features:
  - Color-coded output for success and failure.
  - `--auto-detect` to guess the hash type based on length.
  - `--multi-threaded` mode for faster performance.

## Requirements

- Python 3.x
- `tqdm` library (for progress bar)

### Installation

Install tqdm with:

```
git clone https://github.com/MasterSayantan/Hash-Drill.git
cd Hash-Drill
pip3 install -r requirements.txt
```


## Usage

```bash
python3 Hash-Drill.py -t sha256 -i single_hash.txt -w wordlist.txt
```
if you dont use argument then only run 
```bash
python3 Hash-Drill.py
```
and automatic input field provide, that work as a argument work


### Arguments

- `-t`, `--type`: Hash type (`md5`, `sha1`, `sha256`, `sha512`).
- `-i`, `--input`: Input file containing one or more hashes.
- `-w`, `--wordlist`: Wordlist file for brute force.
- `--auto-detect`: Auto detect hash type based on hash length.
- `--multi-threaded`: Enable multi-threaded cracking.
- `--verbose`: Verbose mode.
- `--silent`: Silent mode (no output except errors).

### Example

```
[🔍] Hash-Drill - Starting SHA256 hash cracking...
[📄] Loaded 4 words from wordlist.txt
[🔐] Target Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
[⚙️ ] Cracking in progress...

Progress: [██████████] 100%
Tried: 4 / 4 passwords
Speed: 10 hashes/sec
Elapsed Time: 0.42s

[✅] Match found!
Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Password: password

[📁] Saved result to output.log
```

## License

MIT License
[📁] Saved result to output.log
python3 Hash-Drill.py -t sha256 -i single_hash.txt -w wordlist.txt
pip install tqdm



### Author Details

- Author: Sayantan Saha  
- LinkedIn: https://linkedin.com/in/mastersayantan  
- GitHub: https://github.com/sayantan-saha-cmd
