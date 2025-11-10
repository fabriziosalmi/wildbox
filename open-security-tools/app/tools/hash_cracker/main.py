"""Hash Cracker Tool - Cracks common hash types using wordlist attacks."""

import hashlib
import time
from datetime import datetime
from typing import List, Optional
try:
    from schemas import HashCrackerInput, HashCrackerOutput, HashResult
except ImportError:
    from schemas import HashCrackerInput, HashCrackerOutput, HashResult

# Common passwords wordlist
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "12345678", "qwerty", "123456789",
    "letmein", "1234567890", "football", "iloveyou", "admin123", "welcome", "monkey",
    "login", "abc123", "starwars", "123123", "dragon", "passw0rd", "master", "hello",
    "freedom", "whatever", "qazwsx", "trustno1", "654321", "jordan23", "harley",
    "password1", "1234", "robert", "matthew", "jordan", "michelle", "love", "jesus",
    "money", "nicole", "hunter", "fuck", "summer", "michael", "sexy", "baby",
    "vanessa", "69696969", "12345", "11111111", "jackson", "q1w2e3r4t5y6", "cameron",
    "liverpool", "buster", "soccer", "hockey", "killer", "george", "sexy", "andrew",
    "charlie", "superman", "asshole", "fuckyou", "dallas", "jessica", "panties",
    "pepper", "1111", "austin", "william", "daniel", "golfer", "summer", "heather",
    "hammer", "yankees", "joshua", "maggie", "biteme", "enter", "ashley", "thunder",
    "cowboy", "silver", "richard", "fucker", "orange", "merlin", "michelle", "corvette",
    "bigdog", "cheese", "matthew", "121212", "patrick", "martin", "freedom", "ginger",
    "blowjob", "nicole", "sparky", "yellow", "camaro", "secret", "dick", "falcon",
    "taylor", "111111", "131313", "123123", "bitch", "hello", "scooter", "please",
    "porsche", "guitar", "chelsea", "black", "diamond", "nascar", "jackson", "cameron",
    "654321", "computer", "amanda", "wizard", "xxxxxx", "money", "phoenix", "mickey",
    "bailey", "knight", "iceman", "tigers", "purple", "andrea", "horny", "dakota",
    "aaaaaa", "player", "sunshine", "morgan", "starwars", "boomer", "cowboys", "edward",
    "charles", "girls", "booboo", "coffee", "xxxxxx", "bulldog", "ncc1701", "rabbit",
    "peanut", "john", "johnny", "gandalf", "spanky", "winter", "brandy", "compaq"
]

ROCKYOU_SAMPLE = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
    "696969", "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "pussy", "superman", "1qaz2wsx", "7777777", "fuckyou", "121212",
    "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "fuckme", "2000", "charlie", "robert", "thomas", "hockey",
    "ranger", "daniel", "starwars", "klaster", "112233", "george", "asshole", "computer",
    "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313",
    "freedom", "777777", "pass", "fuck", "maggie", "159753", "aaaaaa", "ginger",
    "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley", "6969",
    "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321", "dallas",
    "austin", "thunder", "taylor", "matrix", "william", "corvette", "hello", "martin",
    "heather", "secret", "fucker", "merlin", "diamond", "1234qwer", "gfhjkm", "hammer",
    "silver", "222222", "88888888", "anthony", "justin", "test", "bailey", "q1w2e3r4t5",
    "patrick", "internet", "scooter", "orange", "11111", "golfer", "cookie", "richard",
    "samantha", "bigdog", "guitar", "jackson", "whatever", "mickey", "chicken", "sparky",
    "snoopy", "maverick", "phoenix", "camaro", "sexy", "peanut", "morgan", "welcome",
    "falcon", "cowboy", "ferrari", "samsung", "andrea", "smokey", "steelers", "joseph",
    "mercedes", "dakota", "arsenal", "eagles", "melissa", "boomer", "booboo", "spider",
    "nascar", "monster", "tigers", "yellow", "xxxxxx", "123123123", "gateway", "marina",
    "diablo", "bulldog", "qwer1234", "compaq", "purple", "hardcore", "banana", "junior",
    "hannah", "123654", "porsche", "lakers", "iceman", "money", "cowboys", "987654",
    "london", "tennis", "999999", "ncc1701", "coffee", "scooby", "0000", "miller",
    "boston", "q1w2e3r4", "fuckoff", "brandon", "yamaha", "chester", "mother", "forever",
    "johnny", "edward", "333333", "oliver", "redsox", "player", "nikita", "knight",
    "fender", "barney", "midnight", "please", "brandy", "chicago", "badboy", "iwantu",
    "slayer", "rangers", "charles", "angel", "flower", "bigdaddy", "rabbit", "wizard",
    "bigdick", "jasper", "enter", "rachel", "chris", "steven", "winner", "adidas",
    "victoria", "natasha", "1q2w3e4r", "jasmine", "winter", "prince", "panties", "marine"
]

def detect_hash_type(hash_value: str) -> str:
    """Detect hash type based on length and format."""
    hash_value = hash_value.strip().lower()
    
    if len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value):
        return "md5"
    elif len(hash_value) == 40 and all(c in '0123456789abcdef' for c in hash_value):
        return "sha1"
    elif len(hash_value) == 64 and all(c in '0123456789abcdef' for c in hash_value):
        return "sha256"
    elif len(hash_value) == 128 and all(c in '0123456789abcdef' for c in hash_value):
        return "sha512"
    else:
        return "unknown"

def hash_password(password: str, hash_type: str) -> str:
    """
    Hash a password using the specified algorithm.
    
    NOTE: This function intentionally uses weak hashing algorithms (MD5, SHA1)
    for security testing and hash cracking demonstrations only.
    These algorithms should NEVER be used for securing real passwords.
    """
    # Using usedforsecurity=False to indicate these are for testing/cracking purposes only
    if hash_type == "md5":
        return hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode(), usedforsecurity=False).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(password.encode(), usedforsecurity=False).hexdigest()
    else:
        return ""

def get_wordlist(wordlist_type: str, custom_wordlist: Optional[List[str]] = None) -> List[str]:
    """Get wordlist based on type."""
    if wordlist_type == "custom" and custom_wordlist:
        return custom_wordlist
    elif wordlist_type == "rockyou":
        return ROCKYOU_SAMPLE
    else:  # common
        return COMMON_PASSWORDS

def crack_hash(hash_value: str, hash_type: str, wordlist: List[str], max_attempts: int) -> HashResult:
    """Attempt to crack a single hash."""
    start_time = time.time()
    hash_value = hash_value.strip().lower()
    
    # Auto-detect hash type if needed
    if hash_type == "auto":
        hash_type = detect_hash_type(hash_value)
    
    if hash_type == "unknown":
        return HashResult(
            hash_value=hash_value,
            hash_type="unknown",
            cracked=False,
            plaintext=None,
            attempts=0,
            time_taken=time.time() - start_time
        )
    
    attempts = 0
    for password in wordlist:
        if attempts >= max_attempts:
            break
            
        attempts += 1
        hashed = hash_password(password, hash_type)
        
        if hashed == hash_value:
            return HashResult(
                hash_value=hash_value,
                hash_type=hash_type,
                cracked=True,
                plaintext=password,
                attempts=attempts,
                time_taken=time.time() - start_time
            )
    
    return HashResult(
        hash_value=hash_value,
        hash_type=hash_type,
        cracked=False,
        plaintext=None,
        attempts=attempts,
        time_taken=time.time() - start_time
    )

def execute_tool(input_data: HashCrackerInput) -> HashCrackerOutput:
    """Execute the hash cracker tool."""
    timestamp = datetime.now()
    
    # Get wordlist
    wordlist = get_wordlist(input_data.wordlist_type, input_data.custom_wordlist)
    
    # Handle single hash or multiple hashes (split by newlines/commas)
    hash_values = []
    if '\n' in input_data.hash_value or ',' in input_data.hash_value:
        # Multiple hashes
        raw_hashes = input_data.hash_value.replace(',', '\n').split('\n')
        hash_values = [h.strip() for h in raw_hashes if h.strip()]
    else:
        # Single hash
        hash_values = [input_data.hash_value.strip()]
    
    # Crack each hash
    results = []
    for hash_val in hash_values:
        if hash_val:
            result = crack_hash(hash_val, input_data.hash_type, wordlist, input_data.max_attempts)
            results.append(result)
    
    # Calculate statistics
    successful_cracks = sum(1 for r in results if r.cracked)
    statistics = {}
    for result in results:
        hash_type = result.hash_type
        statistics[hash_type] = statistics.get(hash_type, 0) + 1
    
    return HashCrackerOutput(
        timestamp=timestamp,
        total_hashes=len(results),
        successful_cracks=successful_cracks,
        results=results,
        statistics=statistics
    )

# Tool metadata
TOOL_INFO = {
    "name": "hash_cracker",
    "display_name": "Hash Cracker",
    "description": "Cracks common hash types using dictionary attacks",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "cryptography"
}
