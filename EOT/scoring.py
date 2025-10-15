import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .features import extract_all_features, FeatureSet
from .rules import DEFAULT_WEIGHTS, weighted_sum, hard_rules
from .explainability import top_reason_codes

logger = logging.getLogger(__name__)


# --------------------------
# ENUMS
# --------------------------
class RiskStatus(str, Enum):
    LEGITIMO = "LEGITIMO"
    DESCONFIAVEL = "DESCONFIAVEL"
    ALTO_RISCO = "ALTO_RISCO"


class RecommendedAction(str, Enum):
    ALLOW = "allow"
    STEP_UP_AUTH = "step_up_auth"
    BLOCK = "block"


# --------------------------
# DATAMODELS
# --------------------------
@dataclass
class ScoreInput:
    device: Dict[str, Any]
    behavior: Dict[str, Any]
    geo: Dict[str, Any]
    biometrics: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


@dataclass
class ScoreResult:
    score: int
    status: RiskStatus
    recommended_action: RecommendedAction
    reason_codes: List[Dict[str, Any]]
    metadata: Dict[str, Any]


# --------------------------
# CORE FUNCTIONS
# --------------------------
def _calibrate_score(score_raw: float, max_abs_weight: float) -> int:
#    Converte o score bruto (~ -max..+max) para a faixa 0..100.
    if max_abs_weight <= 0:
        max_abs_weight = 1.0

    normalized = max(min(score_raw / max_abs_weight, 1.0), -1.0)  # -1..1
    scaled = (normalized + 1.0) * 50.0                           # 0..100
    return int(round(scaled))


def _map_to_status_action(score: int) -> Tuple[RiskStatus, RecommendedAction]:
#    Mapeia score para status e ação.
    if score >= 75:
        return RiskStatus.LEGITIMO, RecommendedAction.ALLOW
    if score >= 50:
        return RiskStatus.DESCONFIAVEL, RecommendedAction.STEP_UP_AUTH
    return RiskStatus.ALTO_RISCO, RecommendedAction.BLOCK


# --------------------------
# MAIN ENTRYPOINT
# --------------------------
def calculate_score(
    payload: Dict[str, Any],
    weights: Optional[Dict[str, float]] = None
) -> ScoreResult:
    """
    Calcula score de risco baseado em features, regras e pesos.
    """
    logger.debug("Iniciando cálculo de score")
    w = weights or DEFAULT_WEIGHTS

    # 1) Extrair features
    features: FeatureSet = extract_all_features(payload)
    logger.debug(f"Features extraídas: {features}")

    # 2) Aplicar hard rules
    fired_rule, hard_code = hard_rules(features)
    logger.debug(f"Hard rule disparada: {fired_rule}, código: {hard_code}")

    # 3) Calcular score bruto
    score_raw, contributions = weighted_sum(features, w)
    logger.debug(f"Score bruto: {score_raw}, Contribuições: {contributions}")

    # 4) Calibrar score
    dynamic_max = max(1.0, sum(abs(v) for v in w.values()) / 2.0)
    score = _calibrate_score(score_raw, dynamic_max)
    logger.debug(f"Score calibrado: {score}")

    # 5) Mapear para status e ação
    status, action = _map_to_status_action(score)

    # 6) Gerar razões (explainability)
    reasons = top_reason_codes(contributions, top_k=5)
    if fired_rule:
        reasons.insert(0, {"code": hard_code, "contribution": -999.0})

    # 7) Montar metadata
    metadata = {
        "model_version": "v0.1.0",
        "hard_rule_fired": fired_rule,
        "context": payload.get("context", {}),
    }

    logger.info(f"Score final: {score}, Status: {status}, Ação: {action}")

    return ScoreResult(
        score=score,
        status=status,
        recommended_action=action,
        reason_codes=reasons,
        metadata=metadata,
    )
