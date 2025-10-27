### DOKUMENTASI BACKEND

# Testing upload sample
```bash
curl -v \
  -F "file=@./eicar.com" \
  -F "name=EICAR-Test" \
  -F "severity=Low" \
  -F "description=EICAR test upload" \
  http://localhost:8080/api/add-sample
```

