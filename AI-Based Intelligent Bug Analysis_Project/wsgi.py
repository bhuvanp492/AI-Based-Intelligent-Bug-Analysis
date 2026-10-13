"""
WSGI Entry Point for Production Deployment.
Usage with Gunicorn: gunicorn --bind 0.0.0.0:8000 wsgi:app
Usage with Waitress: waitress-serve --port=8000 wsgi:app
"""
import os
from config import ProductionConfig
from app import create_app

# Instantiate application using production configuration
app = create_app(ProductionConfig)

if __name__ == "__main__":
    app.run()
