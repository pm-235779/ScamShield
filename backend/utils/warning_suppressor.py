"""
Warning Suppressor for ML Model Loading
Suppresses sklearn version mismatch warnings during model loading.
"""

import warnings
import functools
from typing import Any, Callable

def suppress_sklearn_warnings(func: Callable) -> Callable:
    """Decorator to suppress sklearn version warnings"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
            warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")
            warnings.filterwarnings("ignore", message=".*Trying to unpickle estimator.*")
            warnings.filterwarnings("ignore", message=".*version.*when using version.*")
            return func(*args, **kwargs)
    return wrapper

def suppress_all_ml_warnings():
    """Globally suppress ML-related warnings"""
    # Sklearn warnings
    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
    warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")
    warnings.filterwarnings("ignore", message=".*Trying to unpickle estimator.*")
    warnings.filterwarnings("ignore", message=".*version.*when using version.*")
    
    # XGBoost warnings
    warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")
    warnings.filterwarnings("ignore", message=".*WARNING.*")
    
    # Joblib warnings
    warnings.filterwarnings("ignore", category=UserWarning, module="joblib")
