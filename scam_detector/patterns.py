"""Pre-defined scam pattern library.

This module contains common scam patterns described in plain English.
Users can use these directly or as templates for custom patterns.
"""

from .models import ScamPattern, RiskLevel


# Financial/Investment Scams

ADVANCE_FEE_SCAM = ScamPattern(
    name="advance_fee",
    description="""
    A scam where the victim is promised a large sum of money, prize, or valuable
    item, but must first pay a fee, tax, or processing charge to receive it.
    The promised reward never materializes after payment.
    """,
    indicators=[
        "Promise of large unexpected windfall (lottery, inheritance, grant)",
        "Request for upfront payment to 'release' or 'process' funds",
        "Urgency or time pressure to pay quickly",
        "Request for payment via untraceable methods (gift cards, crypto, wire)",
        "Claim of official-sounding organization or government agency",
        "Grammar or spelling errors in supposedly official communication",
    ],
    severity=RiskLevel.HIGH,
    examples=[
        "You've won $1,000,000! Pay $500 processing fee to claim.",
        "Your late uncle left you an inheritance, wire $2000 for legal fees.",
        "Government grant approved! Send $100 via gift card to receive $10,000.",
    ],
)

CRYPTO_PUMP_AND_DUMP = ScamPattern(
    name="crypto_pump_dump",
    description="""
    A scheme promoting a cryptocurrency or token with exaggerated claims to
    artificially inflate the price, allowing early holders to sell at a profit
    while later investors lose money when the price crashes.
    """,
    indicators=[
        "Claims of guaranteed or extremely high returns (100x, 1000x)",
        "Urgency to buy before price increases",
        "Celebrity endorsement claims (often fake)",
        "New or unknown token with limited information",
        "Pressure to share or recruit others",
        "Claims of insider information or 'getting in early'",
        "Dismissal of risks or skepticism",
    ],
    severity=RiskLevel.HIGH,
    examples=[
        "This coin is going to 100x next week, buy now before it's too late!",
        "Insider tip: [TOKEN] launching tomorrow, guaranteed moonshot.",
        "Elon just tweeted about this! It's going to explode!",
    ],
)

FAKE_INVESTMENT = ScamPattern(
    name="fake_investment",
    description="""
    Fraudulent investment opportunity promising unrealistic returns with
    little or no risk. Often structured as Ponzi schemes where early
    investors are paid with funds from later investors.
    """,
    indicators=[
        "Guaranteed high returns with no risk",
        "Consistent returns regardless of market conditions",
        "Pressure to invest quickly or increase investment",
        "Difficulty withdrawing funds",
        "Unregistered or unlicensed investment",
        "Complex or secretive investment strategy",
        "Referral bonuses for recruiting others",
    ],
    severity=RiskLevel.CRITICAL,
    examples=[
        "Earn 10% weekly returns guaranteed, no risk!",
        "Our AI trading bot has never had a losing month.",
        "Invest $1000 today, withdraw $5000 next month.",
    ],
)


# E-commerce/Marketplace Scams

FAKE_BUYER = ScamPattern(
    name="fake_buyer",
    description="""
    Scam targeting sellers where a fake buyer pretends interest in purchasing
    an item but aims to defraud the seller through overpayment schemes,
    fake payment confirmations, or requests to ship before payment clears.
    """,
    indicators=[
        "Overpayment with request to refund the difference",
        "Urgency to ship immediately before payment verification",
        "Unusual payment methods or requests",
        "Unwillingness to meet locally for local sales",
        "Generic messages that don't reference the specific item",
        "Request to continue conversation off-platform",
        "Shipping to different address than buyer location",
    ],
    severity=RiskLevel.HIGH,
    examples=[
        "I'll send you $500 extra for shipping, wire back the difference.",
        "Payment sent! Ship now, it's urgent for my son's birthday.",
        "Can we talk on WhatsApp? I have a special payment method.",
    ],
)

FAKE_SELLER = ScamPattern(
    name="fake_seller",
    description="""
    Scam where a fraudulent seller offers items (often at attractive prices)
    but never delivers the goods after receiving payment, or sends
    counterfeit/inferior products.
    """,
    indicators=[
        "Price significantly below market value",
        "Request for payment outside platform protection",
        "New account with no history or reviews",
        "Stock photos or images stolen from elsewhere",
        "Vague or copy-pasted product descriptions",
        "Pressure to buy quickly due to 'limited stock'",
        "Only accepts non-reversible payment methods",
    ],
    severity=RiskLevel.HIGH,
    examples=[
        "Brand new iPhone for $200, Venmo only, selling fast!",
        "PS5 below retail - must pay via Zelle before meeting.",
        "Designer bags 80% off, DM for payment details.",
    ],
)


# Romance/Social Engineering Scams

ROMANCE_SCAM = ScamPattern(
    name="romance_scam",
    description="""
    Scam where fraudster creates fake romantic interest to build emotional
    connection, then exploits that trust to request money for fabricated
    emergencies, travel costs, or investment opportunities.
    """,
    indicators=[
        "Quick progression to declarations of love",
        "Unable to video chat or meet in person",
        "Claims to be overseas (military, oil rig, business)",
        "Eventual request for money for emergencies",
        "Sob stories about sick relatives or lost wallet",
        "Request to receive or forward money/packages",
        "Profile seems too perfect or photos look professional",
    ],
    severity=RiskLevel.HIGH,
    examples=[
        "I'm stuck overseas and lost my wallet, can you wire me $2000?",
        "I want to visit you but need help with the plane ticket.",
        "My mother is sick and I need money for her surgery.",
    ],
)


# Employment Scams

FAKE_JOB = ScamPattern(
    name="fake_job",
    description="""
    Fraudulent job offer designed to steal money or personal information.
    May require payment for training/equipment, or collect sensitive data
    under guise of employment application.
    """,
    indicators=[
        "Job requires upfront payment for training or equipment",
        "Salary too good for the work described",
        "Vague job description or company information",
        "Interview conducted only via text/chat",
        "Requests for sensitive personal information early",
        "Work from home with minimal requirements",
        "Payment in advance of work completion",
    ],
    severity=RiskLevel.HIGH,
    examples=[
        "Make $5000/week working from home, just pay $200 for training.",
        "Hired! Send SSN and bank details to set up direct deposit.",
        "Easy money reshipping packages from home.",
    ],
)

MONEY_MULE = ScamPattern(
    name="money_mule",
    description="""
    Recruitment scheme to use someone's bank account to launder money.
    Victim receives funds (often stolen) and forwards them elsewhere,
    keeping a percentage as 'commission'.
    """,
    indicators=[
        "Job involves receiving and forwarding money",
        "No real product or service being provided",
        "Commission based on money transferred",
        "Urgency to move funds quickly",
        "Communication primarily via messaging apps",
        "Company has no verifiable presence",
        "Task seems too easy for the pay offered",
    ],
    severity=RiskLevel.CRITICAL,
    examples=[
        "Receive payments and forward 90%, keep 10% as your fee.",
        "Work as our payment processor, $500/day for easy transfers.",
        "Help our international company process customer payments.",
    ],
)


# Tech Support/Phishing Scams

TECH_SUPPORT_SCAM = ScamPattern(
    name="tech_support",
    description="""
    Scam where fraudster poses as technical support from a legitimate
    company, claiming the victim's device is infected or compromised,
    then charges for unnecessary services or gains remote access.
    """,
    indicators=[
        "Unsolicited contact about computer problems",
        "Urgent warnings about viruses or hackers",
        "Request for remote access to computer",
        "Payment requested for fixing non-existent problems",
        "Claims to be from Microsoft, Apple, or ISP",
        "Pressure tactics and scare language",
        "Request for payment via gift cards",
    ],
    severity=RiskLevel.HIGH,
    examples=[
        "Microsoft detected a virus on your computer, call now!",
        "Your IP has been compromised, pay $300 to fix.",
        "Allow remote access so we can remove the hackers.",
    ],
)

PHISHING = ScamPattern(
    name="phishing",
    description="""
    Attempt to steal sensitive information by impersonating a legitimate
    entity. Often uses fake websites, emails, or messages that mimic
    trusted organizations to collect login credentials or financial data.
    """,
    indicators=[
        "Urgency to verify account or update information",
        "Link to website with slightly wrong URL",
        "Request for password, PIN, or security codes",
        "Threats of account suspension or closure",
        "Generic greeting instead of your name",
        "Sender email doesn't match company domain",
        "Request to confirm information you never provided",
    ],
    severity=RiskLevel.HIGH,
    examples=[
        "Your account will be suspended! Click here to verify.",
        "Unusual login detected, confirm your password now.",
        "Update your payment method or lose access.",
    ],
)


# Utility function to get all patterns

def get_common_patterns() -> list[ScamPattern]:
    """Get all pre-defined common scam patterns."""
    return [
        ADVANCE_FEE_SCAM,
        CRYPTO_PUMP_AND_DUMP,
        FAKE_INVESTMENT,
        FAKE_BUYER,
        FAKE_SELLER,
        ROMANCE_SCAM,
        FAKE_JOB,
        MONEY_MULE,
        TECH_SUPPORT_SCAM,
        PHISHING,
    ]


def get_financial_patterns() -> list[ScamPattern]:
    """Get patterns related to financial/investment scams."""
    return [
        ADVANCE_FEE_SCAM,
        CRYPTO_PUMP_AND_DUMP,
        FAKE_INVESTMENT,
    ]


def get_marketplace_patterns() -> list[ScamPattern]:
    """Get patterns related to e-commerce/marketplace scams."""
    return [
        FAKE_BUYER,
        FAKE_SELLER,
    ]


def get_employment_patterns() -> list[ScamPattern]:
    """Get patterns related to employment/job scams."""
    return [
        FAKE_JOB,
        MONEY_MULE,
    ]


def get_tech_patterns() -> list[ScamPattern]:
    """Get patterns related to tech support and phishing scams."""
    return [
        TECH_SUPPORT_SCAM,
        PHISHING,
    ]
