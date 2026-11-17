import hashlib
import math
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import List, Optional, Tuple

from app.core.config import settings
from app.db.repository import InMemoryRepository
from app.models.transaction import TransactionStatus
from app.schemas.fraud import FraudEvaluationResponse, RiskFactorDetail, RiskSeverity
from app.schemas.transaction import TransactionCreate

# High risk merchant category codes
HIGH_RISK_MCCS = {
    "7995": "Gambling / Betting",
    "6051": "Cryptocurrency / Quasi-Cash",
    "5967": "Direct Marketing / Adult Content",
    "6211": "High-Risk Securities / Commodities",
    "7273": "Dating / Escort Services",
}


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great circle distance between two points on Earth in kilometers.
    """
    r = 6371.0  # Earth's radius in km
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c


class FraudDetectionEngine:
    """
    Multi-heuristic rule evaluation engine for real-time transaction risk scoring.
    Computes additive risk factors and determines transactional decisioning.
    """

    def __init__(self, repository: InMemoryRepository):
        self.repo = repository

    def evaluate(self, txn: TransactionCreate) -> FraudEvaluationResponse:
        risk_score = 0
        factors: List[RiskFactorDetail] = []
        now = datetime.now(timezone.utc)

        # 1. Blacklist Checks (Immediate critical violation)
        ip_str = str(txn.ip_address)
        if self.repo.is_ip_blacklisted(ip_str):
            factors.append(
                RiskFactorDetail(
                    code="BLACKLISTED_IP",
                    severity=RiskSeverity.CRITICAL,
                    description=f"Transaction originated from known malicious IP: {ip_str}",
                    score_impact=100,
                )
            )
            risk_score += 100

        # Check card fingerprint if card details provided
        if txn.card:
            card_fingerprint = hashlib.sha256(txn.card.card_number.encode("utf-8")).hexdigest()
            if self.repo.is_card_fingerprint_blacklisted(card_fingerprint):
                factors.append(
                    RiskFactorDetail(
                        code="COMPROMISED_CARD",
                        severity=RiskSeverity.CRITICAL,
                        description="Card PAN matches known stolen card repository",
                        score_impact=100,
                    )
                )
                risk_score += 100

        # 2. Transaction Amount Rules
        if txn.amount > Decimal(str(settings.FRAUD_MAX_SINGLE_TRANSACTION_AMOUNT)):
            factors.append(
                RiskFactorDetail(
                    code="EXCESSIVE_TRANSACTION_AMOUNT",
                    severity=RiskSeverity.HIGH,
                    description=f"Amount ({txn.amount} {txn.currency}) exceeds high-value limit of {settings.FRAUD_MAX_SINGLE_TRANSACTION_AMOUNT}",
                    score_impact=50,
                )
            )
            risk_score += 50
        elif txn.amount >= Decimal("5000.00"):
            factors.append(
                RiskFactorDetail(
                    code="HIGH_TRANSACTION_AMOUNT",
                    severity=RiskSeverity.MEDIUM,
                    description=f"Amount ({txn.amount} {txn.currency}) requires secondary review threshold",
                    score_impact=20,
                )
            )
            risk_score += 20

        # 3. High-Risk Merchant Category Code (MCC)
        if txn.merchant_category_code in HIGH_RISK_MCCS:
            mcc_desc = HIGH_RISK_MCCS[txn.merchant_category_code]
            factors.append(
                RiskFactorDetail(
                    code="HIGH_RISK_MCC",
                    severity=RiskSeverity.MEDIUM,
                    description=f"MCC {txn.merchant_category_code} classified as high-risk: {mcc_desc}",
                    score_impact=25,
                )
            )
            risk_score += 25

        # 4. Account Velocity Checks (Spike in transaction count in short window)
        window_start = now - timedelta(seconds=settings.FRAUD_VELOCITY_WINDOW_SECONDS)
        recent_txns = self.repo.get_recent_transactions_for_account(
            txn.account_id, since=window_start
        )
        if len(recent_txns) >= settings.FRAUD_VELOCITY_MAX_COUNT:
            factors.append(
                RiskFactorDetail(
                    code="VELOCITY_SPIKE",
                    severity=RiskSeverity.HIGH,
                    description=f"High velocity: {len(recent_txns)} transactions within {settings.FRAUD_VELOCITY_WINDOW_SECONDS}s window",
                    score_impact=40,
                )
            )
            risk_score += 40

        # 5. Geolocation / Impossible Travel Anomaly
        if txn.location:
            last_txn = self.repo.get_last_transaction_for_account(txn.account_id)
            if last_txn and last_txn.geo_latitude is not None and last_txn.geo_longitude is not None:
                time_diff_hours = (now - last_txn.created_at).total_seconds() / 3600.0
                if 0.001 < time_diff_hours < 4.0:  # within 4 hours
                    distance_km = haversine_distance_km(
                        last_txn.geo_latitude,
                        last_txn.geo_longitude,
                        txn.location.latitude,
                        txn.location.longitude,
                    )
                    speed_kmh = distance_km / time_diff_hours
                    if speed_kmh > settings.FRAUD_IMPOSSIBLE_TRAVEL_KMH:
                        factors.append(
                            RiskFactorDetail(
                                code="IMPOSSIBLE_TRAVEL_VELOCITY",
                                severity=RiskSeverity.HIGH,
                                description=(
                                    f"Impossible travel speed: {speed_kmh:.1f} km/h between locations "
                                    f"({distance_km:.1f} km in {time_diff_hours * 60:.1f} minutes)"
                                ),
                                score_impact=60,
                            )
                        )
                        risk_score += 60

        # Clamp composite risk score to [0, 100]
        final_score = min(max(risk_score, 0), 100)

        # Decision threshold mapping
        if final_score >= settings.FRAUD_HIGH_RISK_THRESHOLD:
            decision = TransactionStatus.REJECTED
            risk_level = "HIGH"
        elif final_score >= settings.FRAUD_REVIEW_THRESHOLD:
            decision = TransactionStatus.FLAGGED
            risk_level = "MEDIUM"
        else:
            decision = TransactionStatus.APPROVED
            risk_level = "LOW"

        return FraudEvaluationResponse(
            decision=decision,
            risk_score=final_score,
            risk_level=risk_level,
            factors=factors,
            evaluated_at=now,
        )
