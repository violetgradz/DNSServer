import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# I found info about Fernet in the cryptography.io docs  
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    # print("Encrypting:", input_string) # used this for debugging
    encrypted_data = f.encrypt(input_string.encode('utf-8')) # encrypt the string after encoding to bytes
    return encrypted_data    

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data) # decrypt the encrypted data
    return decrypted_data.decode('utf-8')

# The assignment said to use 'Tandon' as salt and encode as bytes
salt = b'Tandon'  # I used b prefix to make it bytes
password = "bd2671@nyu.edu"  # My real email
input_string = "AlwaysWatching"  # This is the secret data from the instructions

# Try the encryption
encrypted_value = encrypt_with_aes(input_string, password, salt)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)

# For future use    
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# A dictionary of DNS records - I need to add the records from the assignment
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],  # List of (preference, mail server) tuples
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.', #mname
            'admin.example.com.', #rname
            2023081401, #serial
            3600, #refresh
            1800, #retry
            604800, #expire
            86400, #minimum
        ),
    },
   
    # Adding the A records from the assignment
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    # This one has more records
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        # Making the encrypted value a string for TXT record
        dns.rdatatype.TXT: (str(encrypted_value),),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    }
}

def run_dns_server():
    """
    This function runs the DNS server and responds to requests
    """
    try:
        # Create a UDP socket - port 53 is for DNS according to my research
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(('127.0.0.1', 53))
        
        print("Server is listening on 127.0.0.1:53")
        
        while True:
            # Get the DNS request
            data, addr = server_socket.recvfrom(1024)
            # Parse it using dns.message
            request = dns.message.from_wire(data)
            # Make a response
            response = dns.message.make_response(request)

            # Get the first question (index 0)
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # See if we have that record
            if qname in dns_records and qtype in dns_records[qname]:
                # I have the answer
                answer_data = dns_records[qname][qtype]
                
                # List to hold rdata objects
                rdata_list = []

                # Handle different record types differently
                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    # Needed to figure out SOA format
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)
                else:
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]
                
                # Add all the responses
                for rdata in rdata_list:
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)

            # Set the authoritative answer flag by adding 1 left-shifted by 10 positions
            response.flags |= 1 << 10

            # Send the response back
            print(f"Responding to DNS request for: {qname}, type: {dns.rdatatype.to_text(qtype)}")
            server_socket.sendto(response.to_wire(), addr)
    except KeyboardInterrupt:
        print('\nExiting...')
        server_socket.close()
        sys.exit(0)
    except Exception as e:
        # Added basic error handling
        print(f"Error: {e}")
        server_socket.close()
        sys.exit(1)


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()


if __name__ == '__main__':
    # TODO: test this more with the DNSClient from part 1
    run_dns_server_user()
    # I used these for testing the encryption
    # print("Encrypted Value:", encrypted_value)
    # print("Decrypted Value:", decrypted_value)
