import os

print("Scanning for null bytes...")
for dirpath, dirnames, filenames in os.walk('.'):
    for f in filenames:
        if f.endswith('.py'):
            path = os.path.join(dirpath, f)
            with open(path, 'rb') as fp:
                data = fp.read()
            if b'\x00' in data:
                print(f"Cleaning {path}")
                data = data.replace(b'\x00', b'')
                with open(path, 'wb') as fp:
                    fp.write(data)
print("Done.")