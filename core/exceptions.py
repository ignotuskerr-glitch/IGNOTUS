class IngotusException(Exception):
    """Base exception for Ingotus Recon."""
    pass

class DNSResolutionError(IngotusException):
    """Raised when DNS resolution fails."""
    pass

class HTTPConnectionError(IngotusException):
    """Raised when HTTP request fails."""
    pass

class PortScanError(IngotusException):
    """Raised when port scanning encounters an issue."""
    pass

class TLSAnalysisError(IngotusException):
    """Raised when TLS analysis fails."""
    pass
