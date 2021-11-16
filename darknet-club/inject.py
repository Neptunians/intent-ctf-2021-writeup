out = open('jpeg-payload.js', 'wb')
payload = ''

with open('payload.js', 'rb') as file:
    payload = file.read()

# Fake header
out.write(b'\xff\xd8\xff=1;')
out.write(payload)

out.close()