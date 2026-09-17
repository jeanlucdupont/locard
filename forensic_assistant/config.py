from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    database: str = "data/forensic.db"
    endpoint: str = "http://127.0.0.1:8080"
    timeout: float = 120.0
    batch_size: int = 500
