# Basic example
```bash
for i in {1..6}; do curl -i http://localhost:3000; done
```
# Redis example (requires Redis server)
```bash
curl http://localhost:3000/data
```
# Custom key example
```bash
curl -H "X-API-Key: my-secret-key" http://localhost:3000/profile
```
# Error handling example
```bash
for i in {1..4}; do curl -i http://localhost:3000/api; done
```cd
# Multiple limiters
```bash
curl http://localhost:3000/api/data
```
