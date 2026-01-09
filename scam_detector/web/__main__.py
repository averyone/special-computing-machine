"""Entry point for running the web server directly."""

import uvicorn


def main():
    """Run the web server."""
    uvicorn.run(
        "scam_detector.web.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


if __name__ == "__main__":
    main()
