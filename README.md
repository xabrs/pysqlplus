# pysqlplus

## Description

pySQLPlus - simple lib for querying to AspenTech Infoplus.21 database. The native SQLPLUS protocol is used to connect to the database. This does not require REST, SOAP, ODBC or other technologies

## Usage

`
import sqlplus
s = sqlplus.SQLplus('INFO',10014)
query = "SELECT TS_START, AVG FROM aggregates WHERE name='00AAA01CT001:av' AND 
   ts between '01-FEB-13 00:00' AND '28-FEB-13 00:00'AND period = 864000;"
code, length, res = s.query(query.encode())
if (code!=sqlplus.SQLPLUS_SUCCESS): 
  raise Exception("Query error {}: {}".format(code,res))
print(res.decode())
`


## Protocol decription

The sqlplus server is installed in the INFO server. By default, it listens on TCP port 10014.


### Connection:

1. Connect to the sqlplus server tcp port
2. Send bytes `\x4a\x00\x00\x02\x00`;
3. Server returns name, version, sequence number and string (token)
4. Connect done!


### Query:

1. Increase seq.number by one (4)
2. Append token bytes (36)
3. Append bytes `\x00\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
    \x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb4` (47)
4. Append length of the query string  (4)
5. Append query string bytes
6. Append packet length to the beginning
7. Encrypt the resulting packet by the RC4 algorithm with 8 bytes. For more see advapi32.py.
8. Send to the server


### Response:

1. Accept in a buffer of size 4004;
2. Decrypt the first 4 bytes. This is the packet length;
3. Accept packets until the number of received bytes is less than the packet length. For each recv, decrease the buffer size by the number of received bytes;
4. Decrypt the received packet;
5. The 0th byte contains the return code. 0x53 is normal. Bytes 1-4 contain the message length;
6. Then the result of the request in text form;
7. If the packet length is less than the message length, continue steps 1-7, excluding step 5


## License

This program is free for both personal and commercial use and is licensed under the MIT License.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.