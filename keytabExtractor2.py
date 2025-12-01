#!/usr/bin/env python3
import binascii,sys
import struct



def displayhelp():
    print("Extract ALL keys and hashes from keytab files.")
    print("Based on https://github.com/sosdave/KeyTabExtract. \n\n")
    print("Usage : ./keytabExtractor2.py [keytabfile]")
    print("Example : ./keytabExtractor2.py krb5.keytab")

def ktextract(data):
    # Check for supported encryption types by looking for their enctype hex representation
    hex_encoded = binascii.hexlify(data).decode('utf-8')
    rc4hmac_found = '0017' in hex_encoded # enctype 23 for RC4-HMAC
    aes128_found = '0011' in hex_encoded # enctype 17 for AES128
    aes256_found = '0012' in hex_encoded # enctype 18 for AES256

    if rc4hmac_found:
        print("[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.")
    if aes256_found:
        print("[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.")
    if aes128_found:
        print("[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.")

    if not any([rc4hmac_found, aes128_found, aes256_found]):
        print("[!] No supported encryption types located. Unable to extract hashes.")
        return

    # Keytab file version (2 bytes, big-endian)
    ktversion = struct.unpack('>h', data[0:2])[0]
    if ktversion == 0x0502:
        print("[+] Keytab File version 5.2 successfully imported.")
    else:
        print(f"[!] Only Keytab versions 5.2 are supported (found {ktversion}).\\nExiting...")
        return

    offset = 2  # Start after version
    entry_num = 1

    while offset < len(data):
        # Entry size (4 bytes, big-endian, signed)
        try:
            # If there's not enough data for the size, we're at the end
            if offset + 4 > len(data):
                break
            size = struct.unpack('>i', data[offset:offset+4])[0]
        except struct.error:
            break # End of file
        
        offset += 4
        
        last_entry = False
        if size < 0:
            size = abs(size)
            last_entry = True

        if size == 0:
            continue

        print(f"\n[+] Entry {entry_num}:")
        entry_num += 1

        entry_data = data[offset : offset + size]
        p_offset = 0

        try:
            # Principal Name
            # num_components (2 bytes, big-endian)
            if p_offset + 2 > len(entry_data): raise ValueError("num_components")
            num_components = struct.unpack('>h', entry_data[p_offset:p_offset+2])[0]
            p_offset += 2

            # realm (counted string)
            if p_offset + 2 > len(entry_data): raise ValueError("realm_len")
            realm_len = struct.unpack('>H', entry_data[p_offset:p_offset+2])[0]
            p_offset += 2
            if p_offset + realm_len > len(entry_data): raise ValueError("realm")
            realm = entry_data[p_offset:p_offset + realm_len].decode('utf-8')
            p_offset += realm_len
            print(f"\tREALM : {realm}")

            components = []
            for i in range(num_components):
                if p_offset + 2 > len(entry_data): raise ValueError(f"comp_len_{i+1}")
                comp_len = struct.unpack('>H', entry_data[p_offset:p_offset+2])[0]
                p_offset += 2
                if p_offset + comp_len > len(entry_data): raise ValueError(f"comp_{i+1}")
                component = entry_data[p_offset:p_offset+comp_len].decode('utf-8')
                components.append(component)
                p_offset += comp_len
            
            print(f"\tSERVICE PRINCIPAL : {'/'.join(components)}")

            # name_type (4 bytes, big-endian)
            if p_offset + 4 > len(entry_data): raise ValueError("name_type")
            name_type = struct.unpack('>i', entry_data[p_offset:p_offset+4])[0]
            p_offset += 4

            # timestamp (4 bytes, big-endian, unsigned)
            if p_offset + 4 > len(entry_data): raise ValueError("timestamp")
            timestamp = struct.unpack('>I', entry_data[p_offset:p_offset+4])[0]
            p_offset += 4

            # key version number (1 byte)
            if p_offset + 1 > len(entry_data): raise ValueError("vno")
            vno = struct.unpack('>B', entry_data[p_offset:p_offset+1])[0]
            p_offset += 1

            # key
            if p_offset + 2 > len(entry_data): raise ValueError("keytype")
            keytype = struct.unpack('>h', entry_data[p_offset:p_offset+2])[0]
            p_offset += 2
            if p_offset + 2 > len(entry_data): raise ValueError("keylen")
            keylen = struct.unpack('>H', entry_data[p_offset:p_offset+2])[0]
            p_offset += 2
            if p_offset + keylen > len(entry_data): raise ValueError("keyval")
            keyval = entry_data[p_offset:p_offset + keylen]
            keyval_hex = binascii.hexlify(keyval).decode('utf-8')

            if keytype == 23: # RC4-HMAC
                print(f"\tNTLM HASH : {keyval_hex}")
            elif keytype == 17: # AES128
                print(f"\tAES-128 HASH : {keyval_hex}")
            elif keytype == 18: # AES256
                print(f"\tAES-256 HASH : {keyval_hex}")
            else:
                print(f"\tUnsupported key type ({keytype}) with length {keylen}.")
                print(f"\tKEY VALUE: {keyval_hex}")

        except (struct.error, ValueError, UnicodeDecodeError) as e:
            print(f"\t[!] Error parsing entry: {e}")
            remaining_data_hex = binascii.hexlify(entry_data[p_offset:]).decode('utf-8')
            print(f"\t[!] Remaining entry data ({len(entry_data) - p_offset} bytes): {remaining_data_hex}")

        offset += size
        
        

if __name__ == "__main__":
    if len(sys.argv) < 2:
        displayhelp()
        sys.exit()

    ktfile = sys.argv[1]
    try:
        with open(ktfile, 'rb') as f:
            file_data = f.read()
        ktextract(file_data)
    except FileNotFoundError:
        print(f"[!] File not found: {ktfile}")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
