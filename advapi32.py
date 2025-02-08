from ctypes import FormatError
from ctypes import windll, c_void_p, byref, create_string_buffer, c_int

def assert_success(success):
    if not success:
        raise AssertionError(FormatError())

def CryptAcquireContext():
    hprov = c_void_p()
    success = windll.advapi32.CryptAcquireContextA(byref(hprov), 0, 0, 1, 0xF0000000)
    assert_success(success)
    return hprov

def CryptCreateHash(hProv, Algid):
    hCryptHash = c_void_p()
    success = windll.advapi32.CryptCreateHash(hProv, Algid, 0, 0, byref(hCryptHash))
    assert_success(success)
    return hCryptHash


def CryptHashData(hHash, data):
    bdata = create_string_buffer(data)
    dwdatalen = c_int(len(data))
    success = windll.advapi32.CryptHashData(hHash, bdata, dwdatalen, 0)
    assert_success(success)

def CryptDeriveKey(hProv, Algid, hBaseData):
    hkey = c_void_p()
    success = windll.advapi32.CryptDeriveKey(hProv, Algid, hBaseData, 0x0800000, byref(hkey))
    assert_success(success)
    return hkey

def CryptDecrypt(hkey, encrypted_data,Final=False):
    bdata = create_string_buffer(encrypted_data)
    bdatalen = c_int(len(encrypted_data))
    success = windll.advapi32.CryptDecrypt(hkey, 0, Final, 0, bdata, byref(bdatalen))
    assert_success(success)
    return bdata.raw[:bdatalen.value]


def CryptEncrypt(hkey, plain_data):
    # determine output buffer length
    bdatalen_test = c_int(len(plain_data))
    success = windll.advapi32.CryptEncrypt(hkey, 0, 1, 0, 0, byref(bdatalen_test), len(plain_data))
    assert_success(success)
    out_buf_len = bdatalen_test.value

    # encrypt data
    bdata = create_string_buffer(plain_data, out_buf_len)
    bdatalen = c_int(len(plain_data))
    success = windll.advapi32.CryptEncrypt(hkey, 0, 1, 0, bdata, byref(bdatalen), out_buf_len)
    assert_success(success)
    return bdata.raw[:bdatalen.value]

def format1(data):
    return " ".join("%02x" % a for a in data)

def decrypt(data):
    result = b""
    l = len(data)
    i=0
    while (i+8<l):
        buf = data[i:i+8]
        result += CryptDecrypt(hKey,buf)
        i+=8    

    buf = data[i:]
    result += CryptDecrypt(hKey,buf,True)
    return result

def encrypt(data):
    data_in = b"\x05\x8f\xba\x75\x65\x34\x61\x34\x61\x62\x37\x39\x2d\x38\x66\x38\x30\x2d\x34\x38\x31\x65\x2d\x39\x39\x63\x64\x2d\x66\x33\x33\x61\x64\x36\x38\x34\x39\x64\x65\x37\x00\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb4\x00\x00\x00\x96"
    data_in +=data
    result = b""
    l = len(data_in)
    for x in range(l // 8):
        buf = data_in[x*8:(x+1)*8]
        result += CryptDecrypt(hKey,buf)
    buf = data_in[l-l%8:]
    result += CryptDecrypt(hKey,buf,True) 
    return result

hProv = CryptAcquireContext()
hCryptHash = CryptCreateHash(hProv,0x8003)
CryptHashData(hCryptHash,b"0E2682FF-DA63-4cce-9149-766063556F8F")
hKey = CryptDeriveKey(hProv,0x6801,hCryptHash)