"""Handling of Diffie-Hellman parameter files."""
from .utils.asn1parser import ASN1Parser
from .utils.pem import dePem
from .utils.cryptomath import bytesToNumber

def parseBinary(data):
    """
    Parse DH parameters from ASN.1 DER encoded binary string.

    :param bytes data: DH parameters
    :rtype: tuple of int
    """
    asn1 = ASN1Parser(data); prime = bytesToNumber(asn1.getChild(0).value); generator = bytesToNumber(asn1.getChild(1).value); return generator, prime

def parse(data):
    """
    Parses DH parameters from a binary string.

    The string can either by PEM or DER encoded

    :param bytes data: DH parameters
    :rtype: tuple of int
    :returns: generator and prime
    """
    return parseBinary(dePem(data, "DH PARAMETERS") if b"-----BEGIN" in data else data)
