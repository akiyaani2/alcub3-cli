# packages/core/src/api/security_bridge.py

import sys
import json
from security_framework.src.l1_foundation.model_security import FoundationModelsSecurity, SecurityClassificationLevel

if __name__ == "__main__":
    input_data = json.loads(sys.stdin.read())
    
    classification_level = SecurityClassificationLevel(input_data.get('classification', 'UNCLASSIFIED'))
    security_validator = FoundationModelsSecurity(classification_level)
    
    validation_result = security_validator.validate_input(input_data['text'], input_data.get('context'))
    
    print(json.dumps(validation_result.__dict__))