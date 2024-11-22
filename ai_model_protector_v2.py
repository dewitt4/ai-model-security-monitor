import numpy as np
from typing import Any, Dict, List, Optional, Union
import logging
import hashlib
import json
from datetime import datetime

class AIModelProtector:
    """Security monitoring and protection for AI model deployments"""
    
    def __init__(self, 
                 model_name: str,
                 input_constraints: Dict[str, Any] = None,
                 log_file: Optional[str] = None):
        """
        Initialize the security protector
        
        Args:
            model_name: Identifier for the protected model
            input_constraints: Dictionary of input validation rules
            log_file: Optional custom log file path
        """
        self.model_name = model_name
        self.input_constraints = input_constraints or {}
        self.request_history = []
        
        # Configure logging
        log_file = log_file or f"security_{model_name}_{datetime.now():%Y%m%d}.log"
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def validate_input(self, input_data: Union[np.ndarray, List, Dict]) -> Dict[str, Any]:
        """
        Validate model input against security constraints
        
        Returns:
            Dict containing validation results and any detected issues
        """
        validation_result = {
            "valid": True,
            "issues": []
        }
        
        try:
            # Check for null/empty inputs
            if input_data is None or (hasattr(input_data, "__len__") and len(input_data) == 0):
                validation_result["valid"] = False
                validation_result["issues"].append("Empty or null input detected")
                return validation_result

            # Convert to numpy array for numerical checks
            input_array = np.asarray(input_data)
            
            # Size limits
            if "max_size" in self.input_constraints:
                if input_array.size > self.input_constraints["max_size"]:
                    validation_result["valid"] = False
                    validation_result["issues"].append(f"Input size {input_array.size} exceeds maximum {self.input_constraints['max_size']}")
            
            # Value range checks
            if "max_value" in self.input_constraints:
                if np.any(input_array > self.input_constraints["max_value"]):
                    validation_result["valid"] = False
                    validation_result["issues"].append(f"Values exceed maximum {self.input_constraints['max_value']}")
                    
            if "min_value" in self.input_constraints:
                if np.any(input_array < self.input_constraints["min_value"]):
                    validation_result["valid"] = False
                    validation_result["issues"].append(f"Values below minimum {self.input_constraints['min_value']}")
            
            # Check for anomalous patterns
            anomaly_result = self._check_anomalous_patterns(input_array)
            if anomaly_result["anomalies_detected"]:
                validation_result["valid"] = False
                validation_result["issues"].extend(anomaly_result["details"])
                
        except Exception as e:
            validation_result["valid"] = False
            validation_result["issues"].append(f"Validation error: {str(e)}")
            logging.error(f"Input validation failed: {str(e)}")
            
        return validation_result

    def _check_anomalous_patterns(self, input_array: np.ndarray) -> Dict[str, Any]:
        """
        Check for patterns that might indicate attacks
        """
        result = {
            "anomalies_detected": False,
            "details": []
        }
        
        # Extreme gradients (potential adversarial patterns)
        if len(input_array.shape) > 1:
            gradients = np.gradient(input_array.astype(float))
            max_gradient = self.input_constraints.get("max_gradient", 100)
            if np.any(np.abs(gradients) > max_gradient):
                result["anomalies_detected"] = True
                result["details"].append(f"Extreme gradients detected (>{max_gradient})")
        
        # Unusual sparsity
        sparsity = np.count_nonzero(input_array) / input_array.size
        min_sparsity = self.input_constraints.get("min_sparsity", 0.01)
        if sparsity < min_sparsity:
            result["anomalies_detected"] = True
            result["details"].append(f"Unusually sparse input (sparsity={sparsity:.3f})")
        
        return result
    
    def log_request(self, input_data: Any, metadata: Dict[str, Any] = None) -> None:
        """
        Log request details for monitoring
        """
        try:
            request_hash = hashlib.sha256(
                json.dumps(str(input_data)).encode()
            ).hexdigest()
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "input_hash": request_hash,
                "input_shape": np.asarray(input_data).shape,
                "metadata": metadata or {}
            }
            
            self.request_history.append(log_entry)
            logging.info(f"Request logged: {log_entry}")
            
        except Exception as e:
            logging.error(f"Failed to log request: {str(e)}")

    def analyze_requests(self, window_minutes: int = 60) -> Dict[str, Any]:
        """
        Analyze recent requests for suspicious patterns
        """
        if not self.request_history:
            return {}
            
        cutoff_time = datetime.now().timestamp() - (window_minutes * 60)
        recent_requests = [
            req for req in self.request_history 
            if datetime.fromisoformat(req["timestamp"]).timestamp() > cutoff_time
        ]
        
        analysis = {
            "total_requests": len(recent_requests),
            "unique_inputs": len(set(req["input_hash"] for req in recent_requests)),
            "request_rate": len(recent_requests) / window_minutes,
            "suspicious_patterns": []
        }
        
        # Check for repeated inputs
        hash_counts = {}
        for req in recent_requests:
            hash_counts[req["input_hash"]] = hash_counts.get(req["input_hash"], 0) + 1
            
        # Flag suspicious patterns
        threshold = max(5, len(recent_requests) * 0.1)  # 10% of requests or at least 5
        suspicious = {h: c for h, c in hash_counts.items() if c > threshold}
        if suspicious:
            analysis["suspicious_patterns"].append({
                "type": "repeated_inputs",
                "details": suspicious
            })
            
        return analysis

    def protect(self, input_data: Any, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Main protection function to run before model inference
        
        Returns:
            Dictionary with security assessment and recommendations
        """
        security_report = {
            "timestamp": datetime.now().isoformat(),
            "validation_result": self.validate_input(input_data),
            "request_analysis": self.analyze_requests(),
            "allow_inference": False
        }
        
        # Log the request
        self.log_request(input_data, metadata)
        
        # Determine if inference should be allowed
        security_report["allow_inference"] = (
            security_report["validation_result"]["valid"] and
            not security_report["request_analysis"].get("suspicious_patterns", [])
        )
        
        return security_report
