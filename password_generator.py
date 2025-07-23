import random
import string

def generate_password(length=16, use_symbols=True, use_digits=True) -> str:
    chars = string.ascii_letters
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += string.punctuation
    return ''.join(random.SystemRandom().choice(chars) for _ in range(length))
