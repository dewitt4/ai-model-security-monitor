import numpy as np
from typing import Any, Dict, List, Optional, Union
import logging
import hashlib
import json

class AISecurityMonitor:
    def __init__(self, model_name: str, input_constraints: Dict[str, Any] = None):
        """
        Initialize security monitor for AI model protection.
        
        Args:
            model_name: Name/identifier for the model being protected
            input_constraints: Dictionary of input constraints (e.g. max/min values, allowed types)
        """
        self.model_name = model_name
        self.input_constraints = input_constraints or {}
        self.request_history = []
        
        # Set up logging
        logging.basicConfig(
            filename=f'{model_name}_security.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def validate_input(self, input_data: Union[np.ndarray, List, Dict]) -> bool:
        """
        Validate input data against defined constraints.
        """
        try:
            # Check for null/empty inputs
            if input_data is None or len(input_data) == 0:
                raise ValueError("Empty or null input detected")
            
            # Convert to numpy array if needed
            if isinstance(input_data, (list, dict)):
                input_data = np.array(input_data)
            
            # Check numerical constraints
            if 'max_value' in self.input_constraints:
                if np.any(input_data > self.input_constraints['max_value']):
                    raise ValueError(f"Input exceeds maximum allowed value of {self.input_constraints['max_value']}")
            
            if 'min_value' in self.input_constraints:
                if np.any(input_data < self.input_constraints['min_value']):
                    raise ValueError(f"Input below minimum allowed value of {self.input_constraints['min_value']}")
            
            # Check for adversarial patterns
            if self.detect_adversarial_patterns(input_data):
                raise ValueError("Potential adversarial pattern detected")
            
            return True
            
        except Exception as e:
            logging.warning(f"Input validation failed: {str(e)}")
            return False
    
    def detect_adversarial_patterns(self, input_data: np.ndarray) -> bool:
        """
        Check for common adversarial attack patterns.
        """
        # Check for extreme gradients
        if len(input_data.shape) > 1:
            gradients = np.gradient(input_data.astype(float))
            if np.any(np.abs(gradients) > self.input_constraints.get('max_gradient', 100)):
                return True
        
        # Check for unusual sparsity
        sparsity = np.count_nonzero(input_data) / input_data.size
        if sparsity < self.input_constraints.get('min_sparsity', 0.01):
            return True
            
        return False
    
    def log_request(self, input_data: Any, prediction: Any = None) -> None:
        """
        Log request details for monitoring.
        """
        request_hash = hashlib.sha256(
            json.dumps(input_data, default=str).encode()
        ).hexdigest()
        
        log_entry = {
            'timestamp': logging.Formatter().converter(),
            'input_hash': request_hash,
            'input_shape': np.array(input_data).shape,
            'prediction': prediction
        }
        
        self.request_history.append(log_entry)
        logging.info(f"Request logged: {log_entry}")
    
    def monitor_request_patterns(self, window_size: int = 100) -> Dict[str, Any]:
        """
        Analyze recent requests for suspicious patterns.
        """
        if len(self.request_history) < window_size:
            return {}
        
        recent_requests = self.request_history[-window_size:]
        
        # Check for repeated inputs
        input_hashes = [req['input_hash'] for req in recent_requests]
        hash_counts = {}
        for hash_val in input_hashes:
            hash_counts[hash_val] = hash_counts.get(hash_val, 0) + 1
        
        suspicious_patterns = {
            'repeated_inputs': {h: c for h, c in hash_counts.items() if c > window_size * 0.1},
            'request_rate': len(recent_requests) / window_size
        }
        
        return suspicious_patterns

    def protect(self, input_data: Any) -> Dict[str, Any]:
        """
        Main protection function to be called before model inference.
        """
        security_report = {
            'input_valid': False,
            'suspicious_patterns': None,
            'allow_inference': False
        }
        
        # Validate input
        security_report['input_valid'] = self.validate_input(input_data)
        
        # Check request patterns
        security_report['suspicious_patterns'] = self.monitor_request_patterns()
        
        # Determine if inference should be allowed
        security_report['allow_inference'] = (
            security_report['input_valid'] and
            not security_report['suspicious_patterns'].get('repeated_inputs', {})
        )
        
        # Log the request
        self.log_request(input_data)
        
        return security_report
