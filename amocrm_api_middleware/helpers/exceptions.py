from typing import Optional, Dict, Any, Type


class SegmentError(Exception):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


class UnknownSegmentError(SegmentError):
    def __init__(self, message: str = "segment not found", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)