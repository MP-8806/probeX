from fastapi import FastAPI

app = FastAPI(title="MiniScan API")


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }