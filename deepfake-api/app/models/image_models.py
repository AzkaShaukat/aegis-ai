"""
Image pipeline model definitions.
Architectures match EXACTLY the trained checkpoints.

FreqCNN fix: checkpoint has 4 stages (32->64->128->256->512),
head takes 512 features: BN(512)->Dropout->Linear(512,256)->GELU->BN(256)->Dropout->Linear(256,1)
This was causing the size mismatch error.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    import timm
    TIMM_AVAILABLE = True
except ImportError:
    TIMM_AVAILABLE = False


# ── Model 1: EfficientNet-B4 ──────────────────────────────────────────────────
class DeepfakeEfficientNetB4(nn.Module):
    def __init__(self, pretrained: bool = False):
        super().__init__()
        if not TIMM_AVAILABLE:
            raise ImportError("timm is required: pip install timm")
        self.backbone = timm.create_model(
            "efficientnet_b4", pretrained=pretrained, num_classes=0,
            global_pool="", drop_rate=0.4, drop_path_rate=0.2,
        )
        in_f = self.backbone.num_features  # 1792
        self.head = nn.Sequential(
            nn.AdaptiveAvgPool2d(1), nn.Flatten(),
            nn.BatchNorm1d(in_f), nn.Dropout(p=0.4),
            nn.Linear(in_f, 512), nn.SiLU(),
            nn.BatchNorm1d(512), nn.Dropout(p=0.2),
            nn.Linear(512, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.head(self.backbone(x)).squeeze(1)


# ── Model 2: ViT-B/16 ────────────────────────────────────────────────────────
class DeepfakeViT(nn.Module):
    def __init__(self, pretrained: bool = False):
        super().__init__()
        if not TIMM_AVAILABLE:
            raise ImportError("timm is required: pip install timm")
        self.backbone = timm.create_model(
            "vit_base_patch16_224", pretrained=pretrained, num_classes=0,
            drop_rate=0.1, attn_drop_rate=0.0, drop_path_rate=0.1,
        )
        d = self.backbone.embed_dim  # 768
        self.head = nn.Sequential(
            nn.LayerNorm(d), nn.Dropout(p=0.1),
            nn.Linear(d, 256), nn.GELU(),
            nn.LayerNorm(256), nn.Dropout(p=0.05),
            nn.Linear(256, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.head(self.backbone(x)).squeeze(1)


# ── FreqCNN building blocks ───────────────────────────────────────────────────

class SpectralAttention(nn.Module):
    def __init__(self, ch: int, reduction: int = 8):
        super().__init__()
        self.pool = nn.AdaptiveAvgPool2d(1)
        self.fc = nn.Sequential(
            nn.Linear(ch, max(ch // reduction, 8)),
            nn.ReLU(inplace=True),
            nn.Linear(max(ch // reduction, 8), ch),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        b, c, _, _ = x.shape
        return x * self.fc(self.pool(x).view(b, c)).view(b, c, 1, 1)


class MultiScaleBlock(nn.Module):
    """
    Branches named b1/b3/b5, shortcut named skip.
    MUST match checkpoint key names exactly.
    """
    def __init__(self, in_ch: int, out_ch: int, stride: int = 1):
        super().__init__()
        mid = out_ch // 3
        rem = out_ch - 2 * mid
        self.b1 = nn.Sequential(
            nn.Conv2d(in_ch, mid, 1, stride=stride, bias=False),
            nn.BatchNorm2d(mid), nn.ReLU(inplace=True))
        self.b3 = nn.Sequential(
            nn.Conv2d(in_ch, mid, 3, stride=stride, padding=1, bias=False),
            nn.BatchNorm2d(mid), nn.ReLU(inplace=True))
        self.b5 = nn.Sequential(
            nn.Conv2d(in_ch, rem, 5, stride=stride, padding=2, bias=False),
            nn.BatchNorm2d(rem), nn.ReLU(inplace=True))
        self.attn = SpectralAttention(out_ch)
        self.skip = (
            nn.Sequential(
                nn.Conv2d(in_ch, out_ch, 1, stride=stride, bias=False),
                nn.BatchNorm2d(out_ch),
            ) if in_ch != out_ch or stride != 1 else nn.Identity()
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out = torch.cat([self.b1(x), self.b3(x), self.b5(x)], dim=1)
        return F.relu(self.attn(out) + self.skip(x), inplace=True)


# ── Model 3: FrequencyCNN ─────────────────────────────────────────────────────
# FIXED: 4 stages (s1–s4), output 512 features before head.
# Head: BN(512) -> Dropout -> Linear(512,256) -> GELU -> BN(256) -> Dropout -> Linear(256,1)
# This matches the checkpoint's head layer shapes exactly.
class DeepfakeFreqCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.stem = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1, bias=False),
            nn.BatchNorm2d(32), nn.ReLU(inplace=True),
        )
        # 4 stages: 128->64->32->16->8 spatial, channels 32->64->128->256->512
        self.s1 = MultiScaleBlock(32,  64,  stride=2)
        self.s2 = MultiScaleBlock(64,  128, stride=2)
        self.s3 = MultiScaleBlock(128, 256, stride=2)
        self.s4 = MultiScaleBlock(256, 512, stride=2)  # FIX: was missing

        # Head matches checkpoint: input=512
        self.head = nn.Sequential(
            nn.AdaptiveAvgPool2d(1),
            nn.Flatten(),
            nn.BatchNorm1d(512),       # matches checkpoint head.2.weight [512]
            nn.Dropout(p=0.4),
            nn.Linear(512, 256),       # matches checkpoint head.4.weight [256,512]
            nn.GELU(),
            nn.BatchNorm1d(256),       # matches checkpoint head.6.weight [256]
            nn.Dropout(p=0.2),
            nn.Linear(256, 1),         # matches checkpoint head.8.weight [1,256]
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.stem(x)
        x = self.s1(x)
        x = self.s2(x)
        x = self.s3(x)
        x = self.s4(x)
        return self.head(x).squeeze(1)
