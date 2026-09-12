package shadowscan.core;

import shadowscan.model.RiskLevel;

/**
 * Converts raw API response data into a normalized risk verdict.
 * Scoring thresholds are consistent across all 5 modules but calibrated
 * per-module to reflect the different data semantics of each API.
 */
public final class RiskScorer {

    private RiskScorer() {
        // Utility class — no instantiation
    }

    /**
     * Score email breach results based on number of breaches found.
     *
     * @param breachCount number of breaches the email appeared in
     * @param apiRiskScore optional risk score from XposedOrNot analytics (0-10), or -1 if unavailable
     * @return the assessed risk level
     */
    public static RiskLevel scoreEmail(int breachCount, int apiRiskScore) {
        if (breachCount == 0) return RiskLevel.SAFE;

        // If the API provides its own risk score, factor it in
        if (apiRiskScore >= 8) return RiskLevel.CRITICAL;
        if (apiRiskScore >= 5) return RiskLevel.EXPOSED;

        // Fall back to breach count thresholds
        if (breachCount >= 6) return RiskLevel.CRITICAL;
        if (breachCount >= 3) return RiskLevel.EXPOSED;
        return RiskLevel.CAUTION;
    }

    /**
     * Score password exposure based on how many times it appeared in breaches.
     *
     * @param exposureCount number of times the password was seen in breaches
     * @param isInWordlist whether the password appears in known wordlists
     * @return the assessed risk level
     */
    public static RiskLevel scorePassword(long exposureCount, boolean isInWordlist) {
        if (exposureCount == 0) return RiskLevel.SAFE;
        if (exposureCount >= 10_000 || isInWordlist) return RiskLevel.CRITICAL;
        if (exposureCount >= 100) return RiskLevel.EXPOSED;
        return RiskLevel.CAUTION;
    }

    /**
     * Score username/phone exposure based on number of breach sources found.
     *
     * @param sourceCount number of breach sources the identifier appeared in
     * @return the assessed risk level
     */
    public static RiskLevel scoreLeakCheck(int sourceCount) {
        if (sourceCount == 0) return RiskLevel.SAFE;
        if (sourceCount >= 5) return RiskLevel.CRITICAL;
        if (sourceCount >= 3) return RiskLevel.EXPOSED;
        return RiskLevel.CAUTION;
    }

    /**
     * Score IP reputation based on AbuseIPDB's confidence score.
     * Note: this checks abuse reports, NOT breach exposure — the scoring
     * reflects that distinction.
     *
     * @param abuseConfidenceScore 0-100 abuse confidence from AbuseIPDB
     * @param totalReports total number of abuse reports
     * @return the assessed risk level
     */
    public static RiskLevel scoreIpReputation(int abuseConfidenceScore, int totalReports) {
        if (abuseConfidenceScore == 0 && totalReports == 0) return RiskLevel.SAFE;
        if (abuseConfidenceScore >= 76) return RiskLevel.CRITICAL;
        if (abuseConfidenceScore >= 26) return RiskLevel.EXPOSED;
        return RiskLevel.CAUTION;
    }
}
