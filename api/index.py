from phishing_analyzer.server import create_app

# Vercel serverless entry point.
# It expects the Flask app instance to be named 'app'.
app = create_app()
