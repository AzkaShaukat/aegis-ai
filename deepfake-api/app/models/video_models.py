"""
Video pipeline model definitions.
Architectures match EXACTLY the training notebooks (Test_Notebook_Video.ipynb / NB5).

CRITICAL: attribute names must match checkpoint state_dict keys exactly.

SpatialCNN:          backbone (EffNet-B2, default pool), head (Dropout→Linear→GELU→Dropout→Linear)
FrequencySRMCNN:     srm, channel_proj, backbone (EffNet-B4, default pool), head (same)
TemporalTransformer: encoder (EffNet-B2), proj, cls_token, pos_embed, transformer, head

All spatial models: backbone uses default global_pool='avg' → outputs (B, feat) 1D.
Head has NO AdaptiveAvgPool2d — backbone already pools.
"""
import torch
import torch.nn as nn

try:
    import timm
    TIMM_AVAILABLE = True
except ImportError:
    TIMM_AVAILABLE = False


def _build_srm_weights() -> torch.Tensor:
    import torch
    k1 = torch.tensor([[0.,-1.,0.],[-1.,4.,-1.],[0.,-1.,0.]])/4.
    k2 = torch.tensor([[-1.,2.,-1.],[2.,-4.,2.],[-1.,2.,-1.]])/4.
    k3 = torch.tensor([[1.,-2.,1.],[-2.,4.,-2.],[1.,-2.,1.]])/4.
    return torch.stack([k1,k2,k3],dim=0).unsqueeze(1).repeat(3,1,1,1)


class SpatialCNN(nn.Module):
    """Per-frame texture analysis. backbone→1D pool→Dropout→Linear(256)→Linear(1)."""
    def __init__(self, backbone: str = "efficientnet_b2", pretrained: bool = False):
        super().__init__()
        if not TIMM_AVAILABLE:
            raise ImportError("timm required")
        self.backbone = timm.create_model(backbone, pretrained=pretrained, num_classes=0)
        feat = self.backbone.num_features
        self.head = nn.Sequential(
            nn.Dropout(0.4), nn.Linear(feat, 256), nn.GELU(),
            nn.Dropout(0.3), nn.Linear(256, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.head(self.backbone(x)).squeeze(1)


class TemporalTransformer(nn.Module):
    """
    16-frame sequence Transformer.
    Key names match checkpoint: self.encoder, self.proj, self.pos_embed.
    """
    def __init__(self, backbone: str = "efficientnet_b2", proj_dim: int = 512,
                 n_heads: int = 8, n_layers: int = 4, t_frames: int = 16,
                 pretrained: bool = False):
        super().__init__()
        if not TIMM_AVAILABLE:
            raise ImportError("timm required")
        self.encoder = timm.create_model(backbone, pretrained=pretrained, num_classes=0)
        feat = self.encoder.num_features
        self.proj = nn.Sequential(nn.Linear(feat, proj_dim), nn.LayerNorm(proj_dim))
        self.cls_token = nn.Parameter(torch.zeros(1, 1, proj_dim))
        nn.init.trunc_normal_(self.cls_token, std=0.02)
        self.pos_embed = nn.Parameter(torch.zeros(1, t_frames + 1, proj_dim))
        nn.init.trunc_normal_(self.pos_embed, std=0.02)
        enc_layer = nn.TransformerEncoderLayer(
            d_model=proj_dim, nhead=n_heads, dim_feedforward=proj_dim*4,
            dropout=0.1, activation="gelu", batch_first=True, norm_first=True,
        )
        self.transformer = nn.TransformerEncoder(
            enc_layer, num_layers=n_layers, norm=nn.LayerNorm(proj_dim)
        )
        self.head = nn.Sequential(
            nn.Dropout(0.4), nn.Linear(proj_dim, 256), nn.GELU(),
            nn.Dropout(0.3), nn.Linear(256, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        B, T, C, H, W = x.shape
        feat = self.proj(self.encoder(x.view(B*T, C, H, W))).view(B, T, -1)
        cls  = self.cls_token.expand(B, -1, -1)
        feat = torch.cat([cls, feat], dim=1) + self.pos_embed
        return self.head(self.transformer(feat)[:, 0]).squeeze(1)


class FrequencySRMCNN(nn.Module):
    """
    SRM noise residual CNN.
    Key names match checkpoint: self.srm (NOT srm_layer), self.channel_proj,
    self.backbone (default pool, no global_pool=""), self.head (no AdaptiveAvgPool).
    """
    def __init__(self, backbone: str = "efficientnet_b4", pretrained: bool = False):
        super().__init__()
        if not TIMM_AVAILABLE:
            raise ImportError("timm required")
        self.srm = nn.Conv2d(3, 9, 3, padding=1, groups=3, bias=False)
        self.srm.weight = nn.Parameter(_build_srm_weights(), requires_grad=False)
        self.channel_proj = nn.Sequential(
            nn.Conv2d(9, 3, 1, bias=False), nn.BatchNorm2d(3), nn.ReLU(inplace=True),
        )
        # Default pool → (B, 1792) 1D, no AdaptiveAvgPool needed
        self.backbone = timm.create_model(backbone, pretrained=pretrained, num_classes=0)
        feat = self.backbone.num_features
        self.head = nn.Sequential(
            nn.Dropout(0.4), nn.Linear(feat, 256), nn.GELU(),
            nn.Dropout(0.3), nn.Linear(256, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.head(self.backbone(self.channel_proj(self.srm(x)))).squeeze(1)
