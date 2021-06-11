# ja3-proxy
 
Golang HTTP proxy server for spoofing JA3 fingerprints.

# Usage
```bash
$ ja3proxy 127.0.0.1:3333
```

```python
from http.client import HTTPConnection

ja3_string = "771,49196-49195-49200-49199-159-158-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47-10,0-10-11-13-35-23-65281,29-23-24,0"

conn = HTTPConnection("127.0.0.1", 3333)
conn.set_tunnel(
    host="ja3er.com",
    port=443,
    headers={
        "JA3": ja3_string,
        #"Proxy": "127.0.0.1:8888"
    }
)

conn.request("GET", "/json", headers={"User-Agent": "x"})
resp = conn.getresponse()
print(resp.read())
```
