#!/usr/bin/env python3
"""Async usage example for the scam detection agent.

This example demonstrates:
1. Async analysis of multiple posts
2. Batch processing for efficiency
3. Using with asyncio
"""

import asyncio
from scam_detector import (
    OpenAIClient,
    ScamDetector,
    Post,
    get_common_patterns,
)


async def analyze_forum_posts():
    """Analyze a batch of forum posts asynchronously."""

    # Create client and detector
    client = OpenAIClient(
        base_url="http://localhost:1234/v1",
        model="local-model",
        timeout=120.0,
    )

    detector = ScamDetector(client, patterns=get_common_patterns())

    # Simulated forum posts to analyze
    posts = [
        Post(
            content="Hey, I'm selling my old laptop. $300 OBO, local meetup preferred.",
            author="user123",
        ),
        Post(
            content="""
            URGENT: Your bank account has been compromised!
            Click here immediately to verify your identity: http://totallylegitbank.xyz
            Enter your username, password, and SSN to secure your account.
            """,
            author="bank_security_team",
        ),
        Post(
            content="""
            I've been chatting with this amazing person online for 3 months.
            They say they're a doctor working overseas. They asked me to send
            $5000 for a plane ticket to come visit. Should I do it?
            """,
            author="lonely_heart_42",
        ),
        Post(
            content="""
            Looking for recommendations on good hiking boots for the Pacific
            Northwest. Budget is around $150. Waterproof preferred!
            """,
            author="outdoor_enthusiast",
        ),
    ]

    # Analyze all posts concurrently
    print("Analyzing posts asynchronously...")
    results = await detector.aanalyze_batch(posts)

    # Process results
    for i, result in enumerate(results, 1):
        print(f"\nPost {i}: {result.risk_level.value.upper()}")
        if result.is_scam:
            print(f"  ⚠️  Potential scam detected!")
            print(f"  Summary: {result.summary}")
            for match in result.matched_patterns:
                print(f"  - {match.pattern_name}: {match.confidence:.0%} confidence")
        else:
            print(f"  ✓ No scam indicators found")

    await client.aclose()


async def stream_analyze(posts: list[Post]):
    """Process posts as they come in (streaming simulation)."""

    client = OpenAIClient(base_url="http://localhost:1234/v1")
    detector = ScamDetector(client, patterns=get_common_patterns())

    async def process_post(post: Post, idx: int):
        """Process a single post."""
        result = await detector.aanalyze(post)
        return idx, result

    # Process posts with a semaphore to limit concurrent requests
    semaphore = asyncio.Semaphore(3)  # Max 3 concurrent requests

    async def limited_process(post: Post, idx: int):
        async with semaphore:
            return await process_post(post, idx)

    # Create tasks for all posts
    tasks = [limited_process(post, i) for i, post in enumerate(posts)]

    # Process as they complete
    for coro in asyncio.as_completed(tasks):
        idx, result = await coro
        status = "🔴 SCAM" if result.is_scam else "✅ OK"
        print(f"Post {idx + 1} analyzed: {status} - {result.risk_level.value}")

    await client.aclose()


if __name__ == "__main__":
    asyncio.run(analyze_forum_posts())
