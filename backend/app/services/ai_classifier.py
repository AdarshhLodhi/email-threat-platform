import joblib
import os
from typing import Dict, Any, Optional, List

class AIClassifierService:
    # Model paths for trained scikit-learn models
    MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'classifier.pkl')
    VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'vectorizer.pkl')

    LANG_MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'language_classifier.pkl')
    LANG_VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'language_vectorizer.pkl')

    @staticmethod
    def detect_language(text_content: str) -> str:
        """Detects whether text is in English or Hinglish using the trained language model."""
        if not text_content or not os.path.exists(AIClassifierService.LANG_MODEL_PATH) or not os.path.exists(AIClassifierService.LANG_VECTORIZER_PATH):
            return "English"
        try:
            lang_model = joblib.load(AIClassifierService.LANG_MODEL_PATH)
            lang_vec = joblib.load(AIClassifierService.LANG_VECTORIZER_PATH)
            X_vec = lang_vec.transform([text_content])
            return str(lang_model.predict(X_vec)[0])
        except Exception:
            return "English"

    @staticmethod
    def classify_email(
        text_content: str, 
        headers_info: Dict[str, Any], 
        suspicious_domains: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Classifies the email based on text, headers, and IOC threat intelligence."""
        
        # Check if external VirusTotal intelligence flagged active threats in domains
        has_vt_threat = False
        vt_threat_reasons = []
        if suspicious_domains:
            for d in suspicious_domains:
                reasons = d.get("reasons", [])
                for r in reasons:
                    if "VirusTotal" in r:
                        has_vt_threat = True
                        vt_threat_reasons.append(r)

        detected_lang = AIClassifierService.detect_language(text_content)

        # Check if models exist (for Demo mode fallback)
        if not os.path.exists(AIClassifierService.MODEL_PATH) or not os.path.exists(AIClassifierService.VECTORIZER_PATH):
            res = AIClassifierService._demo_fallback_classification(text_content, headers_info, has_vt_threat, vt_threat_reasons)
            res["language"] = detected_lang
            return res
            
        try:
            model = joblib.load(AIClassifierService.MODEL_PATH)
            vectorizer = joblib.load(AIClassifierService.VECTORIZER_PATH)
            
            # Simple NLP on body text
            X_new = vectorizer.transform([text_content])
            
            # Predict
            prediction = int(model.predict(X_new)[0])
            probabilities = model.predict_proba(X_new)[0]
            confidence = float(probabilities[prediction])
            
            # Map prediction: 0 -> Benign, 1 -> Threat
            text_lower = (text_content or "").lower()
            phishing_signals = any(kw in text_lower for kw in ["account", "password", "verify", "suspend", "login", "reset", "click here", "urgent"])
            malware_signals = any(kw in text_lower for kw in ["invoice", "payment", "remittance", "attached", "attachment", "zip", "exe", "payload"])

            if prediction == 0:
                classification = "Benign"
            else:
                if malware_signals:
                    classification = "Malware"
                elif phishing_signals:
                    classification = "Phishing"
                else:
                    classification = "Threat"

            # Override/boost if VirusTotal verified malicious threat
            if has_vt_threat:
                if classification == "Benign":
                    classification = "Phishing"
                confidence = max(float(confidence), 0.96)
                explanation = f"AI and VirusTotal threat intel classified this communication as {classification} ({confidence*100:.1f}% confidence, language: {detected_lang}). Active vendor detections found."
            else:
                explanation = f"AI model classified this as {classification} ({confidence*100:.1f}% confidence, language: {detected_lang})."
                
            return {
                "classification": classification,
                "confidence": float(confidence),
                "language": detected_lang,
                "explanation": explanation
            }
            
        except Exception as e:
            print(f"Error during AI classification: {e}")
            res = AIClassifierService._demo_fallback_classification(text_content, headers_info, has_vt_threat, vt_threat_reasons)
            res["language"] = detected_lang
            return res

    @staticmethod
    def _demo_fallback_classification(
        text_content: str, 
        headers_info: Dict[str, Any], 
        has_vt_threat: bool = False,
        vt_threat_reasons: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """A heuristic and threat-intel based fallback for demo mode without the ML model."""
        text_lower = text_content.lower()
        
        phishing_keywords = ["urgent", "account suspended", "verify your account", "login", "password reset", "click here"]
        malware_keywords = ["invoice attached", "remittance", "payment confirmation", "wire transfer", "exe", "zip", "payload"]
        
        phishing_score = sum(1 for kw in phishing_keywords if kw in text_lower)
        malware_score = sum(1 for kw in malware_keywords if kw in text_lower)
        
        # If VirusTotal detected malware/phishing on extracted domains
        if has_vt_threat:
            threat_type = "Malware" if malware_score > phishing_score else "Phishing"
            return {
                "classification": threat_type,
                "confidence": 0.96,
                "explanation": f"Confirmed threat: VirusTotal flagged extracted indicators. {'; '.join(vt_threat_reasons or [])}"
            }

        if phishing_score > 0 and malware_score > 0:
            if phishing_score > malware_score:
                return {"classification": "Phishing", "confidence": 0.85, "explanation": "Found multiple phishing keywords."}
            else:
                return {"classification": "Malware", "confidence": 0.88, "explanation": "Found keywords indicating malicious attachments."}
        elif phishing_score > 0:
            return {"classification": "Phishing", "confidence": min(0.95, 0.75 + (phishing_score * 0.05)), "explanation": "Found phishing-related language."}
        elif malware_score > 0:
            return {"classification": "Malware", "confidence": min(0.95, 0.75 + (malware_score * 0.05)), "explanation": "Found language typical of malware delivery."}
            
        return {"classification": "Benign", "confidence": 0.90, "explanation": "No suspicious language or IOC threats detected."}
