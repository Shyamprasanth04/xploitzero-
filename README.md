# Web Application Vulnerability Scanner

## Docker Deployment

### Build the Docker image
```
docker build -t vulnscanner .
```

### Run the Docker container
```
docker run -d -p 5000:5000 --name vulnscanner vulnscanner
```

- The app will be available at http://localhost:5000
- Update environment variables (e.g., SMTP, API key) as needed using `-e` flags or a `.env` file. 