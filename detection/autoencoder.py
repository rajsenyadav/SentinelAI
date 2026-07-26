"""
SentinelAI — Autoencoder Anomaly Detection Model

Deep neural network autoencoder trained to reconstruct normal behavioral features.
Anomalous events exhibit high reconstruction error (MSE) because the model
has only learned compressed representations of normal behavioral dynamics.
"""

import logging
import pickle
from typing import Tuple, Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# Check PyTorch availability
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logger.warning("PyTorch not found. Autoencoder will fallback to PCA reconstruction loss.")


if HAS_TORCH:
    class PyTorchAutoencoderNet(nn.Module):
        """Deep Bottleneck Autoencoder Architecture."""
        def __init__(self, input_dim: int, hidden_dim: int = 16, latent_dim: int = 8):
            super().__init__()
            # Encoder
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(hidden_dim, latent_dim),
                nn.ReLU(),
            )
            # Decoder
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(hidden_dim, input_dim),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            latent = self.encoder(x)
            reconstructed = self.decoder(latent)
            return reconstructed


class AutoencoderModel:
    """
    Autoencoder Anomaly Detector based on reconstruction error (MSE).
    Uses PyTorch when available, falls back to PCA reconstruction error otherwise.
    """

    def __init__(
        self,
        epochs: int = 20,
        batch_size: int = 256,
        learning_rate: float = 1e-3,
        random_state: int = 42,
    ):
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.random_state = random_state

        self.scaler = StandardScaler()
        self.net = None
        self.pca_fallback = None
        self.is_fitted = False

    def fit(self, X: pd.DataFrame) -> "AutoencoderModel":
        """
        Fit Autoencoder on feature matrix X (trained on normal/all features).
        """
        logger.info(f"Fitting Autoencoder on {X.shape[0]} rows, {X.shape[1]} features...")
        X_scaled = self.scaler.fit_transform(X)

        if HAS_TORCH:
            self._fit_pytorch(X_scaled)
        else:
            self._fit_pca_fallback(X_scaled)

        self.is_fitted = True
        logger.info("  Autoencoder fit complete.")
        return self

    def predict_score(self, X: pd.DataFrame) -> np.ndarray:
        """
        Compute reconstruction error per sample normalized to [0, 1].
        Higher score = higher reconstruction error = anomaly.
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before scoring.")

        X_scaled = self.scaler.transform(X)

        if HAS_TORCH and self.net is not None:
            self.net.eval()
            with torch.no_grad():
                tensor_x = torch.tensor(X_scaled, dtype=torch.float32)
                reconstructed = self.net(tensor_x).numpy()
            mse = np.mean((X_scaled - reconstructed) ** 2, axis=1)
        else:
            # PCA reconstruction error fallback
            transformed = self.pca_fallback.transform(X_scaled)
            reconstructed = self.pca_fallback.inverse_transform(transformed)
            mse = np.mean((X_scaled - reconstructed) ** 2, axis=1)

        # Min-Max normalize MSE to [0, 1]
        min_mse = mse.min()
        max_mse = mse.max()
        if max_mse - min_mse > 0:
            norm_scores = (mse - min_mse) / (max_mse - min_mse)
        else:
            norm_scores = np.zeros_like(mse)

        return norm_scores

    def _fit_pytorch(self, X_scaled: np.ndarray) -> None:
        torch.manual_seed(self.random_state)
        input_dim = X_scaled.shape[1]
        self.net = PyTorchAutoencoderNet(input_dim=input_dim)

        dataset = TensorDataset(torch.tensor(X_scaled, dtype=torch.float32))
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        optimizer = optim.Adam(self.net.parameters(), lr=self.learning_rate)
        criterion = nn.MSELoss()

        self.net.train()
        for epoch in range(self.epochs):
            total_loss = 0.0
            for (b_x,) in loader:
                optimizer.zero_grad()
                out = self.net(b_x)
                loss = criterion(out, b_x)
                loss.backward()
                optimizer.step()
                total_loss += loss.item() * len(b_x)
            
            if (epoch + 1) % 5 == 0 or epoch == self.epochs - 1:
                avg_loss = total_loss / len(X_scaled)
                logger.info(f"    Autoencoder Epoch {epoch+1}/{self.epochs} - Loss (MSE): {avg_loss:.6f}")

    def _fit_pca_fallback(self, X_scaled: np.ndarray) -> None:
        from sklearn.decomposition import PCA
        n_components = max(2, min(X_scaled.shape[1] // 2, 10))
        self.pca_fallback = PCA(n_components=n_components, random_state=self.random_state)
        self.pca_fallback.fit(X_scaled)
        logger.info(f"    PCA Autoencoder Fallback fit with {n_components} components.")

    def save(self, filepath: str) -> None:
        """Save model to disk."""
        with open(filepath, "wb") as f:
            pickle.dump({
                "scaler": self.scaler,
                "net_state": self.net.state_dict() if (HAS_TORCH and self.net) else None,
                "input_dim": self.scaler.mean_.shape[0] if self.scaler.mean_ is not None else None,
                "pca_fallback": self.pca_fallback,
                "has_torch": HAS_TORCH,
            }, f)
        logger.info(f"Saved Autoencoder model to {filepath}")

    def load(self, filepath: str) -> "AutoencoderModel":
        """Load model from disk."""
        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.scaler = data["scaler"]
            self.pca_fallback = data.get("pca_fallback")

            if HAS_TORCH and data.get("net_state") is not None:
                input_dim = data["input_dim"]
                self.net = PyTorchAutoencoderNet(input_dim=input_dim)
                self.net.load_state_dict(data["net_state"])

            self.is_fitted = True
        logger.info(f"Loaded Autoencoder model from {filepath}")
        return self
