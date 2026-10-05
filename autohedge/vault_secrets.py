"""
Vault Secret Manager for AutoHedge

This module provides a secure interface to retrieve secrets from HashiCorp Vault.
All secrets are cached in memory with configurable TTL to minimize API calls.
"""

import hvac
import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class VaultSecretManager:
    """
    Manages secure retrieval of secrets from HashiCorp Vault.
    
    Supports caching with TTL to reduce Vault API calls while maintaining security.
    """
    
    def __init__(
        self,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        cache_ttl_seconds: int = 3600,
        verify_tls: bool = True
    ):
        """
        Initialize Vault client.
        
        Args:
            vault_addr: Vault server address (default from VAULT_ADDR env var)
            vault_token: Vault authentication token (default from VAULT_TOKEN env var)
            cache_ttl_seconds: How long to cache secrets (default 1 hour)
            verify_tls: Whether to verify TLS certificates
        """
        self.vault_addr = vault_addr or os.getenv('VAULT_ADDR', 'https://127.0.0.1:8200')
        self.vault_token = vault_token or os.getenv('VAULT_TOKEN')
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.verify_tls = verify_tls
        
        if not self.vault_token:
            raise ValueError("VAULT_TOKEN environment variable not set")
        
        self.client = hvac.Client(
            url=self.vault_addr,
            token=self.vault_token,
            verify=verify_tls
        )
        
        # Cache: {path: (value, expiry_time)}
        self._cache: Dict[str, tuple] = {}
        
        logger.info(f"Initialized Vault client at {self.vault_addr}")
    
    def _is_cache_valid(self, path: str) -> bool:
        """Check if a cached secret is still valid."""
        if path not in self._cache:
            return False
        
        _, expiry_time = self._cache[path]
        return datetime.now() < expiry_time
    
    def _get_cached(self, path: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached secret if valid."""
        if self._is_cache_valid(path):
            value, _ = self._cache[path]
            logger.debug(f"Cache hit for {path}")
            return value
        return None
    
    def _set_cache(self, path: str, value: Dict[str, Any]) -> None:
        """Cache a secret with TTL."""
        expiry_time = datetime.now() + self.cache_ttl
        self._cache[path] = (value, expiry_time)
        logger.debug(f"Cached {path} until {expiry_time}")
    
    def get_secret(self, path: str, key: Optional[str] = None) -> Any:
        """
        Retrieve a secret from Vault.
        
        Args:
            path: Secret path (e.g., 'autohedge/wallet')
            key: Specific key within the secret (e.g., 'private_key')
        
        Returns:
            Secret value or full secret dict if key is None
        
        Raises:
            ValueError: If secret not found
            hvac.exceptions.InvalidPath: If path is invalid
        """
        # Check cache first
        cached = self._get_cached(path)
        if cached:
            if key:
                return cached.get(key)
            return cached
        
        try:
            secret = self.client.secrets.kv.v2.read_secret_version(path=path)
            data = secret['data']['data']
            
            # Cache the result
            self._set_cache(path, data)
            
            if key:
                if key not in data:
                    raise KeyError(f"Key '{key}' not found in secret '{path}'")
                return data[key]
            return data
        
        except hvac.exceptions.InvalidPath:
            logger.error(f"Secret not found at path: {path}")
            raise ValueError(f"Secret not found at path: {path}")
        except hvac.exceptions.Forbidden:
            logger.error(f"Permission denied accessing: {path}")
            raise PermissionError(f"Permission denied accessing: {path}")
        except Exception as e:
            logger.error(f"Error retrieving secret from Vault: {e}")
            raise
    
    def get_wallet_private_key(self) -> str:
        """Retrieve wallet private key from Vault."""
        return self.get_secret('autohedge/wallet', 'private_key')
    
    def get_jupiter_api_key(self) -> str:
        """Retrieve Jupiter API key from Vault."""
        return self.get_secret('autohedge/jupiter', 'api_key')
    
    def get_openai_api_key(self) -> str:
        """Retrieve OpenAI API key from Vault."""
        return self.get_secret('autohedge/openai', 'api_key')
    
    def get_anthropic_api_key(self) -> str:
        """Retrieve Anthropic API key from Vault."""
        return self.get_secret('autohedge/anthropic', 'api_key')
    
    def get_all_autohedge_secrets(self) -> Dict[str, str]:
        """Retrieve all AutoHedge secrets at once."""
        secrets = {
            'wallet_private_key': self.get_wallet_private_key(),
            'jupiter_api_key': self.get_jupiter_api_key(),
            'openai_api_key': self.get_openai_api_key(),
            'anthropic_api_key': self.get_anthropic_api_key(),
        }
        return secrets
    
    def renew_token(self) -> None:
        """Renew the Vault token to prevent expiration."""
        try:
            self.client.auth.token.renew_self()
            logger.info("Vault token renewed successfully")
        except Exception as e:
            logger.error(f"Failed to renew Vault token: {e}")
            raise
    
    def clear_cache(self) -> None:
        """Clear all cached secrets."""
        self._cache.clear()
        logger.info("Secret cache cleared")
    
    def revoke_token(self) -> None:
        """Revoke the Vault token (useful for cleanup)."""
        try:
            self.client.auth.token.revoke_self()
            logger.info("Vault token revoked")
        except Exception as e:
            logger.error(f"Failed to revoke Vault token: {e}")
            raise


# Singleton instance for application-wide use
_vault_instance: Optional[VaultSecretManager] = None


def get_vault_manager() -> VaultSecretManager:
    """
    Get or create the singleton Vault manager instance.
    
    Returns:
        VaultSecretManager instance
    """
    global _vault_instance
    if _vault_instance is None:
        _vault_instance = VaultSecretManager()
    return _vault_instance


def initialize_vault(
    vault_addr: Optional[str] = None,
    vault_token: Optional[str] = None,
    cache_ttl_seconds: int = 3600
) -> VaultSecretManager:
    """
    Initialize the Vault manager with custom settings.
    
    Args:
        vault_addr: Vault server address
        vault_token: Vault authentication token
        cache_ttl_seconds: Cache TTL in seconds
    
    Returns:
        Configured VaultSecretManager instance
    """
    global _vault_instance
    _vault_instance = VaultSecretManager(
        vault_addr=vault_addr,
        vault_token=vault_token,
        cache_ttl_seconds=cache_ttl_seconds
    )
    return _vault_instance


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Initialize Vault manager
        vault = get_vault_manager()
        
        # Retrieve specific secrets
        wallet_key = vault.get_wallet_private_key()
        print(f"✓ Retrieved wallet private key (length: {len(wallet_key)})")
        
        jupiter_key = vault.get_jupiter_api_key()
        print(f"✓ Retrieved Jupiter API key")
        
        # Retrieve all secrets
        all_secrets = vault.get_all_autohedge_secrets()
        print(f"✓ Retrieved {len(all_secrets)} secrets")
        
    except Exception as e:
        print(f"✗ Error: {e}")
