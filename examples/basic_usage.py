#!/usr/bin/env python3
"""Basic usage example for the scam detection agent.

This example demonstrates how to:
1. Configure the OpenAI-compatible client
2. Set up scam patterns (using pre-defined or custom patterns)
3. Analyze posts for scam indicators
"""

from scam_detector import (
    OpenAIClient,
    ScamDetector,
    ScamPattern,
    Post,
    RiskLevel,
    get_common_patterns,
    get_financial_patterns,
)


def main():
    # Configure the client for LM Studio (default local endpoint)
    # Change base_url for other providers:
    # - OpenAI: "https://api.openai.com/v1" (requires api_key)
    # - Ollama: "http://localhost:11434/v1"
    # - vLLM: "http://localhost:8000/v1"
    client = OpenAIClient(
        base_url="http://localhost:1234/v1",  # LM Studio default
        model="local-model",  # Use your loaded model name
        temperature=0.1,  # Low temperature for consistent analysis
    )

    # Create detector with common scam patterns
    detector = ScamDetector(client, patterns=get_common_patterns())

    # Example posts to analyze
    test_posts = [
        # Likely scam - crypto pump and dump
        Post(
            title="🚀 URGENT: This coin is going to 1000x!!!",
            content="""
            Listen up everyone! I have insider info that $MOONCOIN is about to
            explode. The devs are announcing a major partnership tomorrow and
            it's going to go parabolic. I already 10x'd my money and it's just
            getting started. Buy NOW before it's too late! Don't miss out like
            you did with Bitcoin. This is financial freedom calling!
            DM me for the contract address before the whales find out.
            """,
            author="crypto_insider_2024",
        ),

        # Likely legitimate - someone asking for help
        Post(
            title="Need advice on investing in index funds",
            content="""
            Hi everyone, I'm new to investing and have been reading about
            index funds. I have about $5000 saved up and want to start
            investing for retirement. Should I go with a total market fund
            or an S&P 500 fund? Also, is it better to invest all at once
            or dollar cost average? Thanks for any advice!
            """,
            author="new_investor_questions",
        ),

        # Likely scam - advance fee fraud
        Post(
            title="CONGRATULATIONS! You've been selected!",
            content="""
            Dear Lucky Winner,

            You have been randomly selected to receive $2,500,000 USD from
            the Microsoft/Google International Lottery Program! Your email
            was chosen from millions of entries.

            To claim your prize, you must pay a small processing fee of $500
            via Western Union or Bitcoin. Once payment is confirmed, your
            winnings will be transferred within 24 hours.

            Contact our claims agent immediately at winner.claims@gmail.com

            This is TIME SENSITIVE - claim within 48 hours or forfeit!

            Congratulations again!
            Dr. James Wilson
            International Claims Department
            """,
            author="official_lottery_winner",
        ),

        # Likely legitimate - selling used item
        Post(
            title="Selling my PS5 - local pickup only",
            content="""
            Moving and need to sell my PS5 disc edition. Used for about a year,
            works perfectly. Comes with one controller and 3 games (Spider-Man,
            God of War, Horizon). Asking $400 or best offer.

            Local pickup only in downtown Seattle. Can meet at the police
            station parking lot. Cash or Venmo accepted. Happy to test it
            for you before purchase.
            """,
            author="seattle_gamer",
        ),
    ]

    # Analyze each post
    print("=" * 60)
    print("SCAM DETECTION ANALYSIS")
    print("=" * 60)

    for i, post in enumerate(test_posts, 1):
        print(f"\n--- Post {i}: {post.title or 'Untitled'} ---")
        print(f"Author: {post.author or 'Unknown'}")
        print()

        try:
            result = detector.analyze(post)

            # Display risk level with color coding hint
            risk_emoji = {
                RiskLevel.NONE: "✅",
                RiskLevel.LOW: "🟡",
                RiskLevel.MEDIUM: "🟠",
                RiskLevel.HIGH: "🔴",
                RiskLevel.CRITICAL: "🚨",
            }

            print(f"Risk Level: {risk_emoji.get(result.risk_level, '❓')} {result.risk_level.value.upper()}")
            print(f"Summary: {result.summary}")

            if result.matched_patterns:
                print("\nMatched Patterns:")
                for match in result.matched_patterns:
                    print(f"  • {match.pattern_name} (confidence: {match.confidence:.0%})")
                    print(f"    {match.explanation}")
                    if match.evidence:
                        print(f"    Evidence: {', '.join(match.evidence[:3])}")
            else:
                print("\nNo scam patterns detected.")

        except Exception as e:
            print(f"Error analyzing post: {e}")

        print()

    client.close()


def example_custom_pattern():
    """Example of creating a custom scam pattern."""

    # Define a custom pattern for a specific type of scam
    nft_scam = ScamPattern(
        name="nft_rug_pull",
        description="""
        An NFT project that shows signs of being a potential rug pull,
        where creators abandon the project after collecting funds from
        buyers, leaving them with worthless digital assets.
        """,
        indicators=[
            "Anonymous or unverifiable team",
            "Unrealistic roadmap promises",
            "Pressure to mint quickly before 'selling out'",
            "No real utility beyond speculation",
            "Copy-pasted artwork or stolen designs",
            "Fake celebrity endorsements",
            "Discord focused on price and 'floor' rather than project",
        ],
        severity=RiskLevel.HIGH,
        examples=[
            "Limited to 10,000 - minting fast! Don't miss your chance to be early!",
            "Our anonymous team has big plans - trust the process!",
            "Floor is going to 10 ETH easy, this is the next BAYC!",
        ],
    )

    client = OpenAIClient(base_url="http://localhost:1234/v1")
    detector = ScamDetector(client)

    # Add single pattern
    detector.add_pattern(nft_scam)

    # Or add multiple at once
    detector.add_patterns(get_financial_patterns())

    # Now detector will check for NFT rug pulls plus financial scams
    print(f"Detector has {len(detector.patterns)} patterns loaded")

    client.close()


if __name__ == "__main__":
    main()
