from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
import torch
from pytorch_tabnet.callbacks import Callback
from pytorch_tabnet.tab_model import TabNetClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from torch import nn
from torch.utils.data import DataLoader, TensorDataset
from tqdm.auto import tqdm


def compute_balanced_class_weights(
    labels: np.ndarray,
    num_classes: int,
    *,
    power: float = 1.0,
    max_weight: float | None = None,
) -> np.ndarray:
    counts = np.bincount(labels, minlength=num_classes).astype(np.float32)
    safe_counts = np.where(counts == 0, 1.0, counts)
    weights = labels.shape[0] / (num_classes * safe_counts)
    if power != 1.0:
        weights = np.power(weights, power)
    if max_weight is not None and max_weight > 0:
        weights = np.minimum(weights, max_weight)
    return weights.astype(np.float32)


class MultiClassFocalLoss(nn.Module):
    def __init__(self, *, gamma: float = 2.0, alpha: torch.Tensor | None = None) -> None:
        super().__init__()
        self.gamma = gamma
        self.register_buffer("alpha", alpha if alpha is not None else None)

    def forward(self, logits: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
        ce = nn.functional.cross_entropy(logits, target, reduction="none")
        pt = torch.exp(-ce)
        focal = (1 - pt) ** self.gamma * ce

        if self.alpha is not None:
            alpha = self.alpha.to(target.device)
            alpha_t = alpha.gather(0, target)
            focal = alpha_t * focal

        return focal.mean()


class BaseModelAdapter(ABC):
    @abstractmethod
    def fit(self, features: pd.DataFrame, labels: np.ndarray) -> None:
        pass

    @abstractmethod
    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        pass

    @abstractmethod
    def to_payload(self) -> dict[str, Any]:
        pass


class SklearnModelAdapter(BaseModelAdapter):
    def __init__(
        self,
        pipeline: Pipeline | None = None,
        *,
        random_state: int = 42,
        imbalance_strategy: str = "none",
    ) -> None:
        class_weight = "balanced" if imbalance_strategy in {"class_weight", "focal"} else None
        self.pipeline = pipeline or Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                (
                    "classifier",
                    SGDClassifier(
                        loss="log_loss",
                        alpha=1e-4,
                        max_iter=2000,
                        tol=1e-3,
                        random_state=random_state,
                        class_weight=class_weight,
                    ),
                ),
            ]
        )

    def fit(self, features: pd.DataFrame, labels: np.ndarray) -> None:
        self.pipeline.fit(features, labels)

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        return self.pipeline.predict_proba(features)

    def to_payload(self) -> dict[str, Any]:
        return {"pipeline": self.pipeline}

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "SklearnModelAdapter":
        return cls(pipeline=payload["pipeline"])


class TorchMLP(nn.Module):
    def __init__(self, input_dim: int, output_dim: int, hidden_dims: tuple[int, int] = (128, 64)) -> None:
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(input_dim, hidden_dims[0]),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dims[0], hidden_dims[1]),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dims[1], output_dim),
        )

    def forward(self, tensor: torch.Tensor) -> torch.Tensor:
        return self.layers(tensor)


@dataclass(slots=True)
class TorchTrainingConfig:
    epochs: int = 18
    batch_size: int = 512
    learning_rate: float = 1e-3
    weight_decay: float = 1e-5
    focal_gamma: float = 2.0
    class_weight_power: float = 1.0
    class_weight_max: float | None = None


@dataclass(slots=True)
class TabNetTrainingConfig:
    max_epochs: int = 20
    patience: int = 10
    batch_size: int = 8192
    virtual_batch_size: int = 1024
    learning_rate: float = 2e-2
    focal_gamma: float = 2.0
    num_workers: int = 8
    validation_size: float = 0.1
    show_progress: bool = True
    n_d: int = 8
    n_a: int = 8
    n_steps: int = 3
    gamma: float = 1.3
    class_weight_power: float = 1.0
    class_weight_max: float | None = None


def can_stratify_numpy(labels: np.ndarray) -> bool:
    counts = np.bincount(labels)
    non_zero = counts[counts > 0]
    return non_zero.size > 1 and int(non_zero.min()) >= 2


class TabNetProgressCallback(Callback):
    def __init__(self, total_epochs: int, enabled: bool = True) -> None:
        super().__init__()
        self.total_epochs = total_epochs
        self.enabled = enabled
        self.progress: tqdm | None = None

    def on_train_begin(self, logs=None):
        if not self.enabled:
            return
        self.progress = tqdm(total=self.total_epochs, desc="TabNet", unit="epoch")

    def on_epoch_end(self, epoch, logs=None):
        if not self.enabled or self.progress is None:
            return
        self.progress.update(1)
        if logs:
            useful = {key: value for key, value in logs.items() if isinstance(value, (float, int))}
            if useful:
                self.progress.set_postfix({key: f"{value:.4f}" for key, value in useful.items()})

    def on_train_end(self, logs=None):
        if self.progress is not None:
            self.progress.close()
            self.progress = None


class TorchModelAdapter(BaseModelAdapter):
    def __init__(
        self,
        *,
        model: TorchMLP | None = None,
        imputer: SimpleImputer | None = None,
        scaler: StandardScaler | None = None,
        input_dim: int | None = None,
        output_dim: int | None = None,
        hidden_dims: tuple[int, int] = (128, 64),
        config: TorchTrainingConfig | None = None,
        random_state: int = 42,
        imbalance_strategy: str = "none",
    ) -> None:
        self.model = model
        self.imputer = imputer or SimpleImputer(strategy="median")
        self.scaler = scaler or StandardScaler()
        self.input_dim = input_dim
        self.output_dim = output_dim
        self.hidden_dims = hidden_dims
        self.config = config or TorchTrainingConfig()
        self.random_state = random_state
        self.imbalance_strategy = imbalance_strategy
        self.device = torch.device("cpu")

        if self.model is not None:
            self.model.to(self.device)

    def _prepare_features(self, features: pd.DataFrame, *, fit: bool) -> np.ndarray:
        values = features.to_numpy(dtype=np.float32, copy=True)
        if fit:
            values = self.imputer.fit_transform(values)
            values = self.scaler.fit_transform(values)
        else:
            values = self.imputer.transform(values)
            values = self.scaler.transform(values)
        return values.astype(np.float32, copy=False)

    def fit(self, features: pd.DataFrame, labels: np.ndarray) -> None:
        torch.manual_seed(self.random_state)
        np.random.seed(self.random_state)

        x = self._prepare_features(features, fit=True)
        y = labels.astype(np.int64, copy=False)

        self.input_dim = int(x.shape[1])
        self.output_dim = int(np.max(y) + 1)
        self.model = TorchMLP(self.input_dim, self.output_dim, self.hidden_dims).to(self.device)

        dataset = TensorDataset(torch.from_numpy(x), torch.from_numpy(y))
        loader = DataLoader(dataset, batch_size=self.config.batch_size, shuffle=True)

        optimizer = torch.optim.Adam(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )
        class_weights = compute_balanced_class_weights(
            y,
            self.output_dim,
            power=self.config.class_weight_power,
            max_weight=self.config.class_weight_max,
        )
        class_weights_tensor = torch.from_numpy(class_weights).to(self.device)
        if self.imbalance_strategy == "class_weight":
            criterion: nn.Module = nn.CrossEntropyLoss(weight=class_weights_tensor)
        elif self.imbalance_strategy == "focal":
            criterion = MultiClassFocalLoss(gamma=self.config.focal_gamma, alpha=class_weights_tensor)
        else:
            criterion = nn.CrossEntropyLoss()

        self.model.train()
        epoch_bar = tqdm(range(self.config.epochs), desc="TorchMLP", unit="epoch")
        for _ in epoch_bar:
            epoch_loss = 0.0
            steps = 0
            for batch_x, batch_y in loader:
                batch_x = batch_x.to(self.device)
                batch_y = batch_y.to(self.device)

                optimizer.zero_grad()
                logits = self.model(batch_x)
                loss = criterion(logits, batch_y)
                loss.backward()
                optimizer.step()
                epoch_loss += float(loss.item())
                steps += 1

            if steps > 0:
                epoch_bar.set_postfix({"loss": f"{(epoch_loss / steps):.4f}"})

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Torch model is not initialized")

        x = self._prepare_features(features, fit=False)
        tensor = torch.from_numpy(x).to(self.device)

        self.model.eval()
        with torch.no_grad():
            logits = self.model(tensor)
            probs = torch.softmax(logits, dim=1)
        return probs.cpu().numpy()

    def to_payload(self) -> dict[str, Any]:
        if self.model is None or self.input_dim is None or self.output_dim is None:
            raise RuntimeError("Torch model is not initialized")

        return {
            "input_dim": self.input_dim,
            "output_dim": self.output_dim,
            "hidden_dims": self.hidden_dims,
            "state_dict": self.model.state_dict(),
            "imputer": self.imputer,
            "scaler": self.scaler,
            "config": self.config,
            "random_state": self.random_state,
            "imbalance_strategy": self.imbalance_strategy,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "TorchModelAdapter":
        model = TorchMLP(payload["input_dim"], payload["output_dim"], tuple(payload["hidden_dims"]))
        model.load_state_dict(payload["state_dict"])
        model.eval()

        return cls(
            model=model,
            imputer=payload["imputer"],
            scaler=payload["scaler"],
            input_dim=payload["input_dim"],
            output_dim=payload["output_dim"],
            hidden_dims=tuple(payload["hidden_dims"]),
            config=payload.get("config", TorchTrainingConfig()),
            random_state=int(payload.get("random_state", 42)),
            imbalance_strategy=str(payload.get("imbalance_strategy", "none")),
        )


class TabNetModelAdapter(BaseModelAdapter):
    def __init__(
        self,
        *,
        model: TabNetClassifier | None = None,
        imputer: SimpleImputer | None = None,
        scaler: StandardScaler | None = None,
        config: TabNetTrainingConfig | None = None,
        random_state: int = 42,
        imbalance_strategy: str = "none",
    ) -> None:
        self.model = model
        self.imputer = imputer or SimpleImputer(strategy="median")
        self.scaler = scaler or StandardScaler()
        self.config = config or TabNetTrainingConfig()
        self.random_state = random_state
        self.imbalance_strategy = imbalance_strategy
        self.loss_fn: nn.Module | None = None
        device_name = "cuda" if torch.cuda.is_available() else "cpu"

        if self.model is None:
            self.model = TabNetClassifier(
                n_d=self.config.n_d,
                n_a=self.config.n_a,
                n_steps=self.config.n_steps,
                gamma=self.config.gamma,
                seed=random_state,
                optimizer_params={"lr": self.config.learning_rate},
                device_name=device_name,
                verbose=0,
            )

    def _prepare_features(self, features: pd.DataFrame, *, fit: bool) -> np.ndarray:
        values = features.to_numpy(dtype=np.float32, copy=True)
        if fit:
            values = self.imputer.fit_transform(values)
            values = self.scaler.fit_transform(values)
        else:
            values = self.imputer.transform(values)
            values = self.scaler.transform(values)
        return values.astype(np.float32, copy=False)

    def fit(self, features: pd.DataFrame, labels: np.ndarray) -> None:
        if self.model is None:
            raise RuntimeError("TabNet model is not initialized")

        x = self._prepare_features(features, fit=True)
        y = labels.astype(np.int64, copy=False)

        stratify = y if can_stratify_numpy(y) else None
        x_train, x_valid, y_train, y_valid = train_test_split(
            x,
            y,
            test_size=self.config.validation_size,
            random_state=self.random_state,
            stratify=stratify,
        )

        weights: int | dict[int, float] = 0
        if self.imbalance_strategy in {"class_weight", "focal"}:
            class_weights = compute_balanced_class_weights(
                y_train,
                int(np.max(y_train) + 1),
                power=self.config.class_weight_power,
                max_weight=self.config.class_weight_max,
            )
            weights = {index: float(weight) for index, weight in enumerate(class_weights)}

        self.loss_fn = None
        if self.imbalance_strategy == "focal":
            alpha = torch.tensor(list(weights.values()), dtype=torch.float32) if isinstance(weights, dict) else None
            self.loss_fn = MultiClassFocalLoss(gamma=self.config.focal_gamma, alpha=alpha)

        self.model.fit(
            x_train,
            y_train,
            eval_set=[(x_valid, y_valid)],
            eval_name=["valid"],
            eval_metric=["accuracy"],
            loss_fn=self.loss_fn,
            max_epochs=self.config.max_epochs,
            patience=self.config.patience,
            batch_size=self.config.batch_size,
            virtual_batch_size=self.config.virtual_batch_size,
            num_workers=self.config.num_workers,
            drop_last=False,
            weights=weights,
            callbacks=[TabNetProgressCallback(self.config.max_epochs, enabled=self.config.show_progress)],
        )

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("TabNet model is not initialized")

        x = self._prepare_features(features, fit=False)
        probabilities = self.model.predict_proba(x)
        return np.asarray(probabilities, dtype=np.float32)

    def to_payload(self) -> dict[str, Any]:
        if self.model is None:
            raise RuntimeError("TabNet model is not initialized")

        return {
            "model": self.model,
            "imputer": self.imputer,
            "scaler": self.scaler,
            "config": self.config,
            "random_state": self.random_state,
            "imbalance_strategy": self.imbalance_strategy,
            "loss_fn": self.loss_fn,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "TabNetModelAdapter":
        return cls(
            model=payload["model"],
            imputer=payload["imputer"],
            scaler=payload["scaler"],
            config=payload.get("config", TabNetTrainingConfig()),
            random_state=int(payload.get("random_state", 42)),
            imbalance_strategy=str(payload.get("imbalance_strategy", "none")),
        )


def build_model_adapter(
    model_type: str,
    *,
    random_state: int = 42,
    imbalance_strategy: str = "none",
    model_config: dict[str, Any] | None = None,
) -> BaseModelAdapter:
    normalized = model_type.strip().lower()
    model_config = model_config or {}
    torch_defaults = TorchTrainingConfig()
    tabnet_defaults = TabNetTrainingConfig()

    if normalized == "sklearn":
        return SklearnModelAdapter(random_state=random_state, imbalance_strategy=imbalance_strategy)
    if normalized == "pytorch":
        torch_config = TorchTrainingConfig(
            epochs=int(model_config.get("epochs", torch_defaults.epochs)),
            batch_size=int(model_config.get("batch_size", torch_defaults.batch_size)),
            learning_rate=float(model_config.get("learning_rate", torch_defaults.learning_rate)),
            weight_decay=float(model_config.get("weight_decay", torch_defaults.weight_decay)),
            focal_gamma=float(model_config.get("focal_gamma", torch_defaults.focal_gamma)),
            class_weight_power=float(model_config.get("class_weight_power", torch_defaults.class_weight_power)),
            class_weight_max=(
                float(model_config["class_weight_max"])
                if model_config.get("class_weight_max") is not None
                else torch_defaults.class_weight_max
            ),
        )
        return TorchModelAdapter(
            random_state=random_state,
            imbalance_strategy=imbalance_strategy,
            config=torch_config,
        )
    if normalized == "tabnet":
        tabnet_config = TabNetTrainingConfig(
            max_epochs=int(model_config.get("max_epochs", tabnet_defaults.max_epochs)),
            patience=int(model_config.get("patience", tabnet_defaults.patience)),
            batch_size=int(model_config.get("batch_size", tabnet_defaults.batch_size)),
            virtual_batch_size=int(model_config.get("virtual_batch_size", tabnet_defaults.virtual_batch_size)),
            learning_rate=float(model_config.get("learning_rate", tabnet_defaults.learning_rate)),
            focal_gamma=float(model_config.get("focal_gamma", tabnet_defaults.focal_gamma)),
            num_workers=int(model_config.get("num_workers", tabnet_defaults.num_workers)),
            validation_size=float(model_config.get("validation_size", tabnet_defaults.validation_size)),
            show_progress=bool(model_config.get("show_progress", tabnet_defaults.show_progress)),
            n_d=int(model_config.get("n_d", tabnet_defaults.n_d)),
            n_a=int(model_config.get("n_a", tabnet_defaults.n_a)),
            n_steps=int(model_config.get("n_steps", tabnet_defaults.n_steps)),
            gamma=float(model_config.get("gamma", tabnet_defaults.gamma)),
            class_weight_power=float(model_config.get("class_weight_power", tabnet_defaults.class_weight_power)),
            class_weight_max=(
                float(model_config["class_weight_max"])
                if model_config.get("class_weight_max") is not None
                else tabnet_defaults.class_weight_max
            ),
        )
        return TabNetModelAdapter(
            random_state=random_state,
            imbalance_strategy=imbalance_strategy,
            config=tabnet_config,
        )
    raise ValueError(f"Unsupported model_type: {model_type}")


def load_model_adapter(model_type: str, payload: dict[str, Any]) -> BaseModelAdapter:
    normalized = model_type.strip().lower()
    if normalized == "sklearn":
        return SklearnModelAdapter.from_payload(payload)
    if normalized == "pytorch":
        return TorchModelAdapter.from_payload(payload)
    if normalized == "tabnet":
        return TabNetModelAdapter.from_payload(payload)
    raise ValueError(f"Unsupported model_type: {model_type}")