import os
import joblib
import numpy as np
import pandas as pd


MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "anomaly_model.pkl"
)


class CyberGuardAnomalyDetector:

    def __init__(self):
        self.features = None
        self.mean = None
        self.std = None

    def train(self, data):

        features = data.select_dtypes(
            include=["number"]
        ).copy()

        ignored_columns = [
            "label",
            "target",
            "risk_score",
            "anomaly"
        ]

        features = features.drop(
            columns=[
                col for col in ignored_columns
                if col in features.columns
            ],
            errors="ignore"
        )

        if features.empty:
            raise ValueError(
                "No numerical features found."
            )

        self.features = list(features.columns)

        self.mean = features.mean()
        self.std = features.std().replace(0, 1)

        return self

    def predict(self, data):

        result = data.copy()

        features = result[self.features]

        # Calculate standardized distance from normal behaviour
        z_scores = (
            features - self.mean
        ) / self.std

        anomaly_score = np.sqrt(
            (z_scores ** 2).sum(axis=1)
        )

        # Convert anomaly score to 0-100 risk score
        max_score = anomaly_score.max()

        if max_score == 0:
            risk_scores = np.zeros(len(anomaly_score))
        else:
            risk_scores = (
                anomaly_score / max_score
            ) * 100

        risk_scores = np.round(
            np.clip(risk_scores, 0, 100),
            2
        )

        result["risk_score"] = risk_scores

        result["anomaly"] = np.where(
            result["risk_score"] >= 60,
            "Anomaly",
            "Normal"
        )

        result["risk_level"] = result[
            "risk_score"
        ].apply(self._risk_level)

        result["recommended_action"] = result[
            "risk_level"
        ].apply(self._recommended_action)

        return result

    @staticmethod
    def _risk_level(score):

        if score < 30:
            return "Low"

        elif score < 60:
            return "Medium"

        elif score < 80:
            return "High"

        else:
            return "Critical"

    @staticmethod
    def _recommended_action(level):

        actions = {
            "Low": "Allow",
            "Medium": "Monitor",
            "High": "Alert",
            "Critical": "Investigate immediately"
        }

        return actions[level]

    def save_model(self):

        os.makedirs(
            os.path.dirname(MODEL_PATH),
            exist_ok=True
        )

        joblib.dump(
            {
                "features": self.features,
                "mean": self.mean,
                "std": self.std
            },
            MODEL_PATH
        )

        print(
            f"Model saved to: {MODEL_PATH}"
        )


def main():

    print("=" * 60)
    print("       CYBERGUARD ANOMALY DETECTION")
    print("       ANOMALY + RISK SCORING ENGINE")
    print("=" * 60)

    # Temporary demo data.
    # This will later be replaced with the actual
    # CyberGuard dataset provided by the team.

    data = pd.DataFrame({

        "failed_logins": [
            0, 1, 0, 2, 1,
            0, 3, 2, 25, 30
        ],

        "login_attempts": [
            2, 3, 1, 4, 2,
            3, 5, 4, 40, 50
        ],

        "connection_count": [
            10, 12, 8, 15, 11,
            13, 20, 18, 150, 200
        ],

        "data_transferred_mb": [
            20, 25, 15, 30, 22,
            28, 35, 40, 900, 1200
        ]
    })

    detector = CyberGuardAnomalyDetector()

    detector.train(data)

    results = detector.predict(data)

    print("\nDetection Results:\n")

    print(
        results[
            [
                "anomaly",
                "risk_score",
                "risk_level",
                "recommended_action"
            ]
        ].to_string(index=True)
    )

    total = len(results)

    anomalies = (
        results["anomaly"] == "Anomaly"
    ).sum()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    print(f"Total events      : {total}")
    print(f"Anomalies detected: {anomalies}")

    print("\nRisk distribution:")

    print(
        results["risk_level"]
        .value_counts()
        .to_string()
    )

    detector.save_model()

    output_path = os.path.join(
        os.path.dirname(__file__),
        "anomaly_results.csv"
    )

    results.to_csv(
        output_path,
        index=False
    )

    print(
        f"\nResults saved to: {output_path}"
    )

    print(
        "\nCyberGuard anomaly detection completed."
    )


if __name__ == "__main__":
    main()