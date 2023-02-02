#!/usr/bin/env python3
"""
hash_password function to return a hashed password
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """ function that expects one string argument name password and return hashed password
    Args:
        password (str): password
    Returns:
        bytes: a salted, hashed password
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Check if a password is valid
    Args:
        hashed_password (bytes): hashed password
        password (str): string type
    Returns:
        bool: bool
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
