import argparse
import hashlib
import os
import sys
import time
from datetime import datetime
from tqdm import tqdm
from threading import Thread, Lock
from queue import Queue

# ANSI color codes for color output
class Colors:
    GREEN = '\\033[92m'
    RED = '\\033[91m'
    YELLOW = '\\033[93m'
    RESET = '\\033[0m'

SUPPORTED_HASHES = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
}

HASH_LENGTHS = {
    32: 'md5',
    40: 'sha1',
    64: 'sha256',
    128: 'sha512',
}

LOG_FILE = 'output.log'
lock = Lock()

def log_result(hash_value, password):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with lock:
        with open(LOG_FILE, 'a') as f:
            f.write(f'[{timestamp}] Hash: {hash_value} Password: {password}\\n')

def detect_hash_type(hash_value):
    length = len(hash_value)
    return HASH_LENGTHS.get(length, None)

def hash_password(password, algo):
    h = SUPPORTED_HASHES[algo]()
    h.update(password.encode('utf-8'))
    return h.hexdigest()

def crack_hash(hash_value, wordlist, algo, verbose, silent, progress_desc):
    found = False
    tried = 0
    start_time = time.time()
    total = len(wordlist)
    bar_format = '{l_bar}{bar}| {n_fmt}/{total_fmt} passwords Tried Speed: {rate_fmt} Elapsed: {elapsed}'
    bar = tqdm(wordlist, desc=progress_desc, unit='password', disable=silent, bar_format=bar_format)
    for word in bar:
        tried += 1
        word = word.strip()
        hashed = hash_password(word, algo)
        if hashed == hash_value:
            elapsed = time.time() - start_time
            speed = tried / elapsed if elapsed > 0 else tried
            bar.n = total
            bar.refresh()
            bar.close()
            if not silent:
                print(f"{Colors.GREEN}[✅] Match found!{Colors.RESET}")
                print(f"Hash: {hash_value}")
                print(f"Password: {word}")
                print(f"Speed: {speed:.2f} hashes/sec")
                print(f"Elapsed Time: {elapsed:.2f}s")
                print(f"[📁] Saved result to {LOG_FILE}")
            log_result(hash_value, word)
            found = True
            break
        if verbose and not silent:
            bar.set_postfix(tried=tried)
    if not found and not silent:
        print(f"{Colors.RED}[❌] No match found for hash: {hash_value}{Colors.RESET}")
    return found

def worker(queue, wordlist, algo, verbose, silent, results):
    while True:
        item = queue.get()
        if item is None:
            break
        hash_value = item
        progress_desc = f"Cracking {hash_value[:8]}..."
        found = crack_hash(hash_value, wordlist, algo, verbose, silent, progress_desc)
        results[hash_value] = found
        queue.task_done()

def main():
    # Print logo with color light_salmon3
    logo = """
          _   _           _           ____       _ _ _ 
         | | | | __ _ ___| |__       |  _ \ _ __(_) | |
         | |_| |/ _` / __| '_ \ _____| | | | '__| | | |
         |  _  | (_| \__ \ | | |_____| |_| | |  | | | |
         |_| |_|\__,_|___/_| |_|     |____/|_|  |_|_|_|
                                              
❖━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━❖
✦  Created By       : Sayantan Saha                              ✦
✦  LinkedIn Profile : https://www.linkedin.com/in/mastersayantan ✦
✦  GitHub Profile   : https://github.com/sayantan-saha-cmd       ✦
❖━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━❖
"""
    # ANSI escape code for light_salmon3 color (RGB 205, 129, 98)
    # Using 24-bit color escape sequence
    color_code = '\033[38;2;205;129;98m'
    reset_code = '\033[0m'
    print(color_code + logo + reset_code)

    # Helper function to print colored input prompt
    def colored_input(prompt):
        return input(color_code + prompt + reset_code)

    parser = argparse.ArgumentParser(description='HashCracker - Smart Terminal-based Hash Cracking Tool')
    parser.add_argument('-t', '--type', choices=SUPPORTED_HASHES.keys(), help='Hash type input field (md5, sha1, sha256, sha512)')
    parser.add_argument('-i', '--input', help='Path of hash file input field with single or multiple hashes')
    parser.add_argument('-w', '--wordlist', help='Wordlist path input field for brute force')
    parser.add_argument('--auto-detect', action='store_true', help='Auto detect hash type based on length')
    parser.add_argument('--multi-threaded', action='store_true', help='Enable multi-threaded cracking')
    parser.add_argument('--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('--silent', action='store_true', help='Silent mode (no output except errors)')
    args = parser.parse_args()
    # Interactive prompts if required arguments are missing
    if not args.type:
        print("Select Hash Type:")
        for i, htype in enumerate(SUPPORTED_HASHES.keys(), 1):
            print(color_code + f"{i}. {htype}" + reset_code)
        print(color_code + f"5. Auto Detect" + reset_code)
        choice = colored_input("Enter choice number: ").strip()
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(SUPPORTED_HASHES):
                args.type = list(SUPPORTED_HASHES.keys())[choice_num - 1]
            elif choice_num == 5:
                args.type = None
                args.auto_detect = True
            else:
                print("Invalid choice. Exiting.")
                sys.exit(1)
        except:
            print("Invalid input. Exiting.")
            sys.exit(1)

    if not args.input:
        args.input = colored_input("Path of hash file: ").strip()
    if not args.wordlist:
        args.wordlist = colored_input("Wordlist path: ").strip()

    # Interactive prompt for multi-threaded option (optional)
    if not args.multi_threaded:
        use_mt = colored_input("Enable multi-threaded cracking? Type 'yes' to enable, anything else to skip: ").strip().lower()
        if use_mt == 'yes':
            args.multi_threaded = True
        else:
            args.multi_threaded = False

    if args.verbose and args.silent:
        print("Cannot use both --verbose and --silent modes together.")
        sys.exit(1)

    if not os.path.isfile(args.input):
        print(f"Input file not found: {args.input}")
        sys.exit(1)

    if not os.path.isfile(args.wordlist):
        print(f"Wordlist file not found: {args.wordlist}")
        sys.exit(1)

    with open(args.input, 'r') as f:
        hashes = [line.strip() for line in f if line.strip()]

    if len(hashes) == 0:
        print("No hashes found in input file.")
        sys.exit(1)

    # Batch mode confirmation if multiple hashes
    if len(hashes) > 1:
        confirm = input(f"Multiple hashes detected ({len(hashes)}). Proceed with batch cracking? Type 'yes' to confirm: ").strip().lower()
        if confirm != 'yes':
            print("Batch cracking cancelled by user.")
            sys.exit(0)

    with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        wordlist = [line.strip() for line in f if line.strip()]

    if len(wordlist) == 0:
        print("Wordlist is empty.")
        sys.exit(1)

    if args.verbose and not args.silent:
        print(f"[📄] Loaded {len(wordlist)} words from {args.wordlist}")

    results = {}

    if args.multi_threaded:
        if args.verbose and not args.silent:
            print("[⚙️ ] Starting multi-threaded cracking...")

        queue = Queue()
        num_threads = min(8, len(hashes))
        threads = []
        for _ in range(num_threads):
            t = Thread(target=worker, args=(queue, wordlist, args.type, args.verbose, args.silent, results))
            t.start()
            threads.append(t)

        for h in hashes:
            if args.auto_detect:
                detected = detect_hash_type(h)
                if detected is None:
                    print(f"Could not auto-detect hash type for: {h}")
                    continue
                else:
                    args.type = detected
                    if args.verbose and not args.silent:
                        print(f"[🔍] Auto-detected hash type: {detected} for hash {h}")
            elif args.type is None:
                print("Hash type must be specified if not using --auto-detect.")
                sys.exit(1)

            queue.put(h)

        queue.join()

        for _ in range(num_threads):
            queue.put(None)
        for t in threads:
            t.join()

    else:
        for h in hashes:
            if args.auto_detect:
                detected = detect_hash_type(h)
                if detected is None:
                    print(f"Could not auto-detect hash type for: {h}")
                    continue
                else:
                    args.type = detected
                    if args.verbose and not args.silent:
                        print(f"[🔍] Auto-detected hash type: {detected} for hash {h}")
            elif args.type is None:
                print("Hash type must be specified if not using --auto-detect.")
                sys.exit(1)

            if args.verbose and not args.silent:
                print(f"[🔐] Target Hash: {h}")
                print("[⚙️ ] Cracking in progress...")

            crack_hash(h, wordlist, args.type, args.verbose, args.silent, "Progress")

if __name__ == '__main__':
    main()
